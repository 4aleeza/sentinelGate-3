"""Lab POC: deterministic rules, in-memory state, lost on restart."""
from collections import Counter, deque
from datetime import datetime, timezone
import time

NOTICE = 'Lab POC: deterministic rules, in-memory state, lost on restart'
BUCKETS = (10, 25, 50, 100, 250, 500, 1000, 2500)
REASONS = frozenset(('allowed','banned','rate_limited','state_capacity','missing_token','malformed_token','expired_token','bad_signature','bad_algorithm','bad_claims','insufficient_scope','bad_method','bad_path','bad_request','bad_content_type','body_too_large','suspicious_pattern','other'))
STATUSES = frozenset((200, 400, 401, 403, 404, 405, 413, 415, 422, 429, 500, 502, 503, 504))

class Observability:
    def __init__(self, clock=time.monotonic, wall_clock=None):
        self.clock = clock
        self.wall_clock = wall_clock or (lambda: datetime.now(timezone.utc))
        self.started = self.clock()
        self.start_time = self.wall_clock().isoformat()
        self.events = deque(maxlen=200)
        self.total_requests = self.monitor_requests = self.api_requests = 0
        self.allowed = self.rejected = self.upstream_errors = 0
        self.bans_issued = self.ban_expiries = self.rate_limited = 0
        self.reasons = Counter(); self.statuses = Counter()
        self.latency_count = 0; self.latency_sum_ms = 0.0; self.latency_max_ms = 0.0
        self.buckets = {str(b): 0 for b in BUCKETS}; self.buckets['+Inf'] = 0
        self.api_latency = {'count':0, 'sum':0.0, 'max':0.0, 'buckets':{**{str(b):0 for b in BUCKETS}, '+Inf':0}}

    def record(self, *, request_id, client_ip, method, path, decision, reason, status, score_after, tier, latency_ms, monitor=False, api=False):
        self.total_requests += 1
        self.monitor_requests += int(monitor); self.api_requests += int(api)
        self.allowed += int(decision == 'allow'); self.rejected += int(decision != 'allow')
        self.reasons[reason if reason in REASONS else 'other'] += 1
        self.statuses[str(status) if status in STATUSES else 'other'] += 1
        self.upstream_errors += int(status in (502, 504))
        self.rate_limited += int(reason == 'rate_limited')
        self.latency_count += 1; self.latency_sum_ms += latency_ms
        self.latency_max_ms = max(self.latency_max_ms, latency_ms)
        for bound in BUCKETS:
            if latency_ms <= bound: self.buckets[str(bound)] += 1
        self.buckets['+Inf'] += 1
        if api:
            histogram = self.api_latency
            histogram['count'] += 1
            histogram['sum'] += latency_ms
            histogram['max'] = max(histogram['max'], latency_ms)
            for bound in BUCKETS:
                if latency_ms <= bound: histogram['buckets'][str(bound)] += 1
            histogram['buckets']['+Inf'] += 1
        self.events.append({'timestamp':self.wall_clock().isoformat(), 'request_id':request_id, 'client_ip':client_ip,
                            'method':method, 'path':path[:256], 'decision':decision, 'reason':reason,
                            'status':status, 'score_after':score_after, 'tier':tier})

    def envelope(self):
        return {'notice':NOTICE, 'start_time':self.start_time, 'uptime_seconds':max(0.0,self.clock()-self.started)}