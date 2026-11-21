"""Synchronous per-IP state; no await during updates. One worker only."""
from dataclasses import dataclass
import math
import time

from .security_config import SecurityConfig


@dataclass
class ClientState:
    tokens: float
    bucket_at: float
    score: float
    score_at: float
    last_seen: float
    ban_until: float = 0.0
    last_ban: float = -math.inf
    offences: int = 0


class CapacityError(Exception):
    pass


class RiskStore:
    def __init__(self, config: SecurityConfig, clock=time.monotonic):
        self.config = config
        self.clock = clock
        self.clients: dict[str, ClientState] = {}
        self.bans_issued = 0
        self.ban_expiries = 0

    def _refresh(self, state, now):
        c = self.config
        if state.ban_until and now >= state.ban_until:
            self.ban_expiries += 1
            expiry = state.ban_until
            state.ban_until = 0.0
            state.score = c.probation_score
            state.score_at = expiry
        elapsed = max(0.0, now - state.bucket_at)
        elevated_for = 0.0
        if state.score >= c.elevated_threshold:
            elevated_for = elapsed if c.decay_per_second == 0 else min(elapsed, (state.score - c.elevated_threshold) / c.decay_per_second)
            state.tokens = min(c.bucket_capacity * c.elevated_factor,
                               state.tokens + elevated_for * c.bucket_refill_per_second * c.elevated_factor)
        state.tokens = min(c.bucket_capacity, state.tokens + (elapsed - elevated_for) * c.bucket_refill_per_second)
        if not state.ban_until:
            state.score = max(0.0, state.score - max(0.0, now - state.score_at) * c.decay_per_second)
            state.score_at = now
        if state.score >= c.elevated_threshold:
            state.tokens = min(state.tokens, c.bucket_capacity * c.elevated_factor)
        state.bucket_at = now

    def get(self, ip):
        now = self.clock()
        if ip not in self.clients:
            if len(self.clients) >= self.config.max_ips:
                idle = []
                for key, state in self.clients.items():
                    self._refresh(state, now)
                    if not state.ban_until and state.score == 0 and state.tokens >= self.config.bucket_capacity:
                        idle.append((state.last_seen, key))
                expired = [key for seen, key in idle if now - seen >= self.config.idle_seconds]
                for key in expired:
                    del self.clients[key]
                if len(self.clients) >= self.config.max_ips and idle:
                    available = [(seen, key) for seen, key in idle if key in self.clients]
                    if available:
                        del self.clients[min(available)[1]]
                if len(self.clients) >= self.config.max_ips:
                    raise CapacityError("No idle state available for eviction")
            self.clients[ip] = ClientState(self.config.bucket_capacity, now, 0.0, now, now)
        state = self.clients[ip]
        self._refresh(state, now)
        state.last_seen = now
        return state

    def ban_remaining(self, state):
        return max(0, math.ceil(state.ban_until - self.clock()))

    def take_token(self, state):
        factor = self.config.elevated_factor if state.score >= self.config.elevated_threshold else 1.0
        if state.tokens >= 1:
            state.tokens -= 1
            return 0
        return max(1, math.ceil((1 - state.tokens) / (self.config.bucket_refill_per_second * factor)))

    def record(self, state, reason):
        now = self.clock()
        before = state.score
        state.score = min(self.config.score_max, before + getattr(self.config, "points_" + reason))
        state.score_at = now
        if state.score >= self.config.ban_threshold and not state.ban_until:
            if now - state.last_ban > self.config.offence_memory_seconds:
                state.offences = 0
            state.offences += 1
            duration = min(self.config.ban_max_seconds, self.config.ban_base_seconds * (2 ** min(state.offences - 1, 32)))
            self.bans_issued += 1
            state.ban_until = now + duration
            state.last_ban = now
        return before, state.score
