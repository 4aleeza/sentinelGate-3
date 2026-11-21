"""Deterministic lab security checks; state is local to one worker only."""
import json
import logging
import os
import re
import time
from urllib.parse import parse_qsl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import unquote

import jwt
from jwt import exceptions as jwt_errors

from .risk_state import CapacityError, RiskStore
from .security_config import SecurityConfig

logger = logging.getLogger('sentinelgate.security')


@dataclass(frozen=True)
class Decision:
    allow: bool
    status: int
    reason: str
    client_ip: str
    headers: dict = field(default_factory=dict)
    score_before: float = 0
    score_after: float = 0
    ban_remaining: int = 0


class SecurityEngine:
    def __init__(self, config: SecurityConfig, secret: str, clock=None, wall_clock=time.time):
        if len(secret.encode()) < 32:
            raise ValueError('SENTINELGATE_JWT_SECRET must contain at least 32 bytes')
        self.config = config
        self.secret = secret
        self.wall_clock = wall_clock
        self.store = RiskStore(config, **({'clock': clock} if clock else {}))

    @classmethod
    def from_environment(cls, clock=None, wall_clock=time.time):
        return cls(SecurityConfig.from_env(), os.getenv('SENTINELGATE_JWT_SECRET', ''), clock, wall_clock)

    def reject(self, state, ip, reason, status, headers=None):
        before, after = self.store.record(state, reason)
        return Decision(False, status, reason, ip, headers or {}, before, after, self.store.ban_remaining(state))

    def begin(self, ip):
        try:
            state = self.store.get(ip)
        except CapacityError:
            return None, Decision(False, 503, 'state_capacity', ip)
        remaining = self.store.ban_remaining(state)
        if remaining:
            return state, Decision(False, 403, 'banned', ip, {'Retry-After': str(remaining)}, state.score, state.score, remaining)
        retry = self.store.take_token(state)
        if retry:
            return state, self.reject(state, ip, 'rate_limited', 429, {'Retry-After': str(retry)})
        return state, None

    def authenticate(self, state, ip, authorization, method):
        auth_headers = {'WWW-Authenticate': 'Bearer'}
        def reject(reason, status=401):
            return self.reject(state, ip, reason, status, auth_headers if status == 401 else {})
        if not authorization:
            return reject('missing_token')
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer' or len(parts[1].encode()) > self.config.max_token_bytes:
            return reject('malformed_token')
        token = parts[1]
        try:
            header = jwt.get_unverified_header(token)
        except jwt_errors.DecodeError:
            return reject('malformed_token')
        if header.get('alg') != 'HS256':
            return reject('bad_algorithm')
        try:
            claims = jwt.decode(token, self.secret, algorithms=['HS256'], issuer=self.config.issuer,
                audience=self.config.audience, leeway=self.config.jwt_leeway_seconds,
                options={'require': ['sub', 'exp', 'iat', 'iss', 'aud', 'scope'],
                         'verify_exp': False, 'verify_iat': False, 'verify_nbf': False})
        except jwt_errors.ExpiredSignatureError:
            return reject('expired_token')
        except jwt_errors.InvalidSignatureError:
            return reject('bad_signature')
        except jwt_errors.DecodeError:
            return reject('malformed_token')
        except jwt_errors.InvalidTokenError:
            return reject('bad_claims')
        if not isinstance(claims.get('sub'), str) or not claims['sub'] or not isinstance(claims.get('scope'), str):
            return reject('bad_claims')
        now = self.wall_clock()
        try:
            exp, iat = float(claims['exp']), float(claims['iat'])
            nbf = float(claims['nbf']) if 'nbf' in claims else None
            if not all(__import__('math').isfinite(v) for v in (exp, iat) + ((nbf,) if nbf is not None else ())):
                return reject('bad_claims')
        except (ValueError, TypeError, OverflowError):
            return reject('bad_claims')
        if exp <= now - self.config.jwt_leeway_seconds:
            return reject('expired_token')
        if iat > now + self.config.jwt_leeway_seconds or (nbf is not None and nbf > now + self.config.jwt_leeway_seconds):
            return reject('bad_claims')
        scope = 'api:read' if method in ('GET', 'HEAD') else 'api:write'
        if scope not in claims['scope'].split():
            return reject('insufficient_scope', 403)
        return None

    def validate_structure(self, state, ip, method, raw_path, path, query, raw_headers):
        c = self.config
        if method not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'):
            return self.reject(state, ip, 'bad_method', 405)
        lower_raw = raw_path.lower()
        decoded = unquote(path)
        if (any(x in lower_raw for x in ('%2e', '%2f', '%5c')) or '..' in decoded
                or '\\' in decoded or any(ord(x) < 32 or ord(x) == 127 for x in decoded)
                or len(raw_path.encode()) > c.max_path_bytes
                or not re.fullmatch(r'/api/[A-Za-z0-9._~/-]{0,' + str(c.max_path_pattern_chars) + '}', decoded)):
            return self.reject(state, ip, 'bad_path', 400)
        if (len(query.encode()) > c.max_query_bytes or len(query.split('&')) > c.max_query_params and query
                or len(raw_headers) > c.max_headers
                or any(len(value) > c.max_header_value_bytes for _, value in raw_headers)):
            return self.reject(state, ip, 'bad_request', 400)
        return None

    def validate_body(self, state, ip, method, content_type, body):
        if len(body) > self.config.max_body_bytes:
            return self.reject(state, ip, 'body_too_large', 413), None
        if method in ('POST', 'PUT', 'PATCH'):
            if content_type.split(';', 1)[0].strip().lower() != 'application/json':
                return self.reject(state, ip, 'bad_content_type', 415), None
            try:
                return None, json.loads(body)
            except (ValueError, UnicodeDecodeError):
                return self.reject(state, ip, 'bad_request', 400), None
        return None, None

    def screen_request(self, request):
        result = self._screen_request(request)
        score = result.score_after
        tier = 'banned' if result.ban_remaining else ('elevated' if score >= self.config.elevated_threshold else 'normal')
        logger.info(json.dumps({'timestamp': datetime.fromtimestamp(self.wall_clock(), timezone.utc).isoformat(),
            'request_id': request.request_id, 'client_ip': result.client_ip, 'method': request.method,
            'path': request.path[:self.config.max_path_bytes], 'decision': 'allow' if result.allow else 'reject',
            'reason': result.reason, 'status': result.status, 'score_before': result.score_before,
            'score_after': score, 'tier': tier, 'ban_remaining': result.ban_remaining}))
        return result

    def _screen_request(self, request):
        """Screen a request-like object; its `client_ip` must be the TCP peer."""
        ip = request.client_ip
        state, decision = self.begin(ip)
        if decision:
            return decision
        before = state.score
        if request.path in ('/health', '/ready'):
            return Decision(True, 200, 'allowed', ip, score_before=before, score_after=state.score)
        decision = self.validate_structure(state, ip, request.method, request.raw_path, request.path,
                                           request.query, request.raw_headers)
        if decision:
            return decision
        decision, parsed = self.validate_body(state, ip, request.method, request.headers.get('content-type', ''), request.body)
        if decision:
            return decision
        def strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, list):
                for item in value: yield from strings(item)
            elif isinstance(value, dict):
                for item in value.values(): yield from strings(item)
        samples = [unquote(request.path), *(v for _, v in parse_qsl(request.query, keep_blank_values=True)), *strings(parsed)]
        patterns = ('../', '<script', "' or 1=1", 'union select', '${jndi:')
        suspicious = any(pattern in sample.lower() for sample in samples for pattern in patterns)
        if suspicious:
            self.store.record(state, 'suspicious_pattern')
        decision = self.authenticate(state, ip, request.headers.get('authorization', ''), request.method)
        if decision:
            return decision
        return Decision(True, 200, 'suspicious_pattern' if suspicious else 'allowed', ip,
                        score_before=before, score_after=state.score, ban_remaining=self.store.ban_remaining(state))


@dataclass(frozen=True)
class SecurityRequest:
    client_ip: str
    request_id: str = ''
    method: str = 'GET'
    path: str = '/api/info'
    raw_path: str = '/api/info'
    query: str = ''
    headers: dict = field(default_factory=dict)
    raw_headers: tuple = ()
    body: bytes = b''


def screen_request(request, engine):
    return engine.screen_request(request)
