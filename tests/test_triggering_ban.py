import jwt
from gateway.security import SecurityEngine, SecurityRequest
from gateway.security_config import SecurityConfig

SECRET = 'test-only-secret-that-is-at-least-32-bytes'

def test_auth_event_that_crosses_threshold_is_denied():
    e = SecurityEngine(SecurityConfig(), SECRET, clock=lambda: 1000, wall_clock=lambda: 1000)
    bad = jwt.encode({'sub': 'x'}, 'wrong-secret', algorithm='HS256')
    r = SecurityRequest('10.10.1.11', headers={'authorization': 'Bearer '+bad})
    for _ in range(3): assert e.screen_request(r).reason == 'bad_signature'
    d = e.screen_request(r)
    assert not d.allow and d.status == 403 and d.reason == 'banned' and d.score_after == 80

def test_suspicious_event_that_crosses_threshold_is_denied():
    e = SecurityEngine(SecurityConfig(), SECRET, clock=lambda: 1000, wall_clock=lambda: 1000)
    s = e.store.get('10.10.1.11')
    e.store.record(s, 'bad_algorithm'); e.store.record(s, 'suspicious_pattern')
    r = SecurityRequest('10.10.1.11', query='q=union+select')
    d = e.screen_request(r)
    assert not d.allow and d.status == 403 and d.reason == 'banned' and d.score_after == 70
