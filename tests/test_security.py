from dataclasses import replace
import jwt
import pytest
import logging
from gateway.security import SecurityEngine, SecurityRequest
from gateway.security_config import SecurityConfig

SECRET = 'test-only-secret-that-is-at-least-32-bytes'

class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, n): self.t += n

@pytest.fixture
def setup():
    clock = Clock()
    return SecurityEngine(SecurityConfig(), SECRET, clock=clock, wall_clock=clock), clock

def token(clock, **changes):
    claims = {'sub':'student','iat':clock.t,'exp':clock.t+100,'iss':'sentinelgate-lab','aud':'sentinelgate-api','scope':'api:read api:write'}
    claims.update(changes)
    return jwt.encode(claims, SECRET, algorithm='HS256')

def req(tok=None, **changes):
    headers = {'authorization':'Bearer '+tok} if tok else {}
    return replace(SecurityRequest('10.10.1.10', headers=headers), **changes)

def test_allow_and_spoofed_forwarding_identity(setup):
    engine, clock = setup
    r = req(token(clock)); r.headers['x-forwarded-for'] = '1.2.3.4'
    result = engine.screen_request(r)
    assert result.allow and result.client_ip == '10.10.1.10'
    assert '1.2.3.4' not in engine.store.clients

@pytest.mark.parametrize('kind,reason', [
    ('missing','missing_token'),('malformed','malformed_token'),('expired','expired_token'),
    ('signature','bad_signature'),('none','bad_algorithm'),('wrong_algorithm','bad_algorithm'),
    ('issuer','bad_claims'),('audience','bad_claims'),('claim','bad_claims'),('scope','insufficient_scope')])
def test_jwt_rejections(setup, kind, reason):
    engine, clock = setup
    t = token(clock)
    if kind == 'missing': t = None
    if kind == 'malformed': t = 'garbage'
    if kind == 'expired': t = token(clock, exp=clock.t-6)
    if kind == 'signature': t = jwt.encode({'sub':'x'}, 'wrong-secret', algorithm='HS256')
    if kind == 'none': t = jwt.encode({'sub':'x'}, key='', algorithm='none')
    if kind == 'wrong_algorithm': t = jwt.encode({'sub':'x'}, SECRET, algorithm='HS384')
    if kind == 'issuer': t = token(clock, iss='wrong')
    if kind == 'audience': t = token(clock, aud='wrong')
    if kind == 'claim': t = jwt.encode({'sub':'x','exp':1100,'iat':1000,'iss':'sentinelgate-lab','aud':'sentinelgate-api'}, SECRET, algorithm='HS256')
    if kind == 'scope': t = token(clock, scope='api:write')
    result = engine.screen_request(req(t))
    assert not result.allow and result.reason == reason
    if result.status == 401: assert result.headers['WWW-Authenticate'] == 'Bearer'

def test_claim_leeway_edges(setup):
    engine, clock = setup
    assert engine.screen_request(req(token(clock, exp=996))).allow
    assert engine.screen_request(req(token(clock, exp=995))).reason == 'expired_token'
    assert engine.screen_request(req(token(clock, iat=1005, nbf=1005))).allow
    assert engine.screen_request(req(token(clock, iat=1006))).reason == 'bad_claims'
    assert engine.screen_request(req(token(clock, nbf=1006))).reason == 'bad_claims'

@pytest.mark.parametrize('updates,reason', [
    ({'method':'TRACE'},'bad_method'),({'path':'/api/../x','raw_path':'/api/../x'},'bad_path'),
    ({'path':'/api/a/b','raw_path':'/api/a%2fb'},'bad_path'),
    ({'path':'/api/x','raw_path':'/api/%2e%2e/x'},'bad_path'),
    ({'path':'/api/\\x','raw_path':'/api/\\x'},'bad_path'),
    ({'query':'a='+'x'*512},'bad_request'),({'raw_headers':((b'x',b'a'*2049),)},'bad_request'),
    ({'method':'POST','headers':{'content-type':'text/plain'},'body':b'{}'},'bad_content_type'),
    ({'method':'POST','headers':{'content-type':'application/json'},'body':b'no'},'bad_request'),
    ({'method':'POST','headers':{'content-type':'application/json'},'body':b'x'*65537},'body_too_large')])
def test_structural_rejections(setup, updates, reason):
    engine, clock = setup
    assert engine.screen_request(req(token(clock), **updates)).reason == reason

def test_suspicious_is_scored_and_allowed(setup):
    engine, clock = setup
    d = engine.screen_request(req(token(clock), query='q=union+select'))
    assert d.allow and d.reason == 'suspicious_pattern' and d.score_after == 15

@pytest.mark.parametrize('query,body', [
    ('q=%3Cscript', None), ('q=%24%7Bjndi%3Aldap', None),
    ('', b'{"nested":{"value":"union select"}}')])
def test_suspicious_sources(setup, query, body):
    engine, clock = setup; r = req(token(clock), query=query)
    if body is not None:
        r = replace(r, method='POST', headers={**r.headers, 'content-type':'application/json'}, body=body)
    result = engine.screen_request(r)
    assert result.allow and result.reason == 'suspicious_pattern' and result.score_after == 15

def test_ban_does_not_extend_and_exact_expiry(setup):
    engine, clock = setup
    for _ in range(2): engine.screen_request(req(jwt.encode({'sub':'x'}, SECRET, algorithm='HS384')))
    state = engine.store.clients['10.10.1.10']; end = state.ban_until
    clock.advance(10)
    d = engine.screen_request(req(None)); assert d.reason == 'banned' and state.ban_until == end
    clock.advance(20)
    assert engine.screen_request(req(token(clock))).allow and state.score == 30

def test_deterministic():
    def run():
        clock=Clock(); engine=SecurityEngine(SecurityConfig(), SECRET, clock=clock, wall_clock=clock)
        return [engine.screen_request(req(None)), engine.screen_request(req(token(clock)))]
    assert run() == run()

def test_missing_or_short_secret_rejected():
    with pytest.raises(ValueError): SecurityEngine(SecurityConfig(), '')
    with pytest.raises(ValueError): SecurityEngine(SecurityConfig(), 'x'*31)

def test_token_length_and_claim_types(setup):
    engine, clock = setup
    assert engine.screen_request(req('x'*4097)).reason == 'malformed_token'
    assert engine.screen_request(req(token(clock, sub=''))).reason == 'bad_claims'
    assert engine.screen_request(req(token(clock, scope=['api:read']))).reason == 'bad_claims'

def test_counts_lengths_and_path_controls(setup):
    engine, clock = setup
    t = token(clock)
    requests = [
        (dict(path='/api/'+('a'*251), raw_path='/api/'+('a'*251)), 'bad_path'),
        (dict(path='/api/a\x00b', raw_path='/api/a\x00b'), 'bad_path'),
        (dict(query='&'.join('x=1' for _ in range(21))), 'bad_request'),
        (dict(raw_headers=tuple((b'x',b'y') for _ in range(51))), 'bad_request')]
    for index, (kw, reason) in enumerate(requests):
        r = req(t, client_ip=f'10.0.0.{index}', **kw)
        assert engine.screen_request(r).reason == reason

def test_each_ip_has_independent_buckets_and_spoof_does_not_change_limit(setup):
    engine, clock = setup; valid = token(clock)
    r = req(valid); r.headers['x-forwarded-for'] = '203.0.113.4'
    for _ in range(20): assert engine.screen_request(r).allow
    assert engine.screen_request(r).reason == 'rate_limited'
    assert engine.screen_request(replace(r, client_ip='10.10.1.11')).allow

def test_health_is_banned_but_skips_auth(setup):
    engine, clock = setup
    health = SecurityRequest('10.10.1.10', path='/health', raw_path='/health')
    assert engine.screen_request(health).allow
    bad = req(jwt.encode({'sub':'x'}, SECRET, algorithm='HS384'))
    engine.screen_request(bad); engine.screen_request(bad)
    assert engine.screen_request(health).reason == 'banned'

def test_success_does_not_credit_score(setup):
    engine, clock = setup
    engine.screen_request(req(None)); state = engine.store.clients['10.10.1.10']
    assert state.score == 5
    assert engine.screen_request(req(token(clock))).allow
    assert state.score == 5

def test_blocked_request_never_reaches_mock_backend(setup):
    engine, clock = setup
    called = []
    def proxy(r):
        decision = engine.screen_request(r)
        if decision.allow: called.append('backend')
        return decision
    assert proxy(req(token(clock))).allow and called == ['backend']
    bad = jwt.encode({'sub':'x'}, SECRET, algorithm='HS384')
    proxy(req(bad)); proxy(req(bad)); before = list(called)
    assert proxy(req(token(clock))).reason == 'banned' and called == before

def test_retry_after_from_actual_refill(setup):
    engine, clock = setup
    r = req(token(clock))
    for _ in range(20): assert engine.screen_request(r).allow
    result = engine.screen_request(r)
    assert result.status == 429 and result.headers['Retry-After'] == '1'
    clock.advance(0.1)
    assert engine.screen_request(r).allow

def test_decision_log_excludes_credentials(setup, caplog):
    engine, clock = setup; credential = token(clock)
    security_logger = logging.getLogger('sentinelgate.security')
    security_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level(logging.INFO, logger='sentinelgate.security'):
            engine.screen_request(req(credential))
    finally:
        security_logger.removeHandler(caplog.handler)
    assert '"decision": "allow"' in caplog.text
    assert credential not in caplog.text and SECRET not in caplog.text

@pytest.mark.parametrize('claim,value', [('sub', 123), ('exp', 'not-a-number'), ('iat', []), ('scope', 3), ('scope', ['api:read'])])
def test_malformed_claim_values(setup, claim, value):
    engine, clock = setup
    assert engine.screen_request(req(token(clock, **{claim: value}))).reason == 'bad_claims'

@pytest.mark.parametrize('missing', ['sub', 'exp', 'iat', 'iss', 'aud', 'scope'])
def test_each_required_claim_is_enforced(setup, missing):
    engine, clock = setup
    claims = {'sub':'student','iat':clock.t,'exp':clock.t+100,'iss':'sentinelgate-lab','aud':'sentinelgate-api','scope':'api:read'}
    del claims[missing]
    assert engine.screen_request(req(jwt.encode(claims, SECRET, algorithm='HS256'))).reason == 'bad_claims'

@pytest.mark.parametrize('name,value', [('SG_BUCKET_CAPACITY','0'), ('SG_MAX_IPS','0'), ('SG_BAN_BASE_SECONDS','-1'), ('SG_BUCKET_REFILL_PER_SECOND','invalid')])
def test_invalid_configuration_is_rejected(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        SecurityConfig.from_env()

def test_capacity_rejection():
    clock = Clock()
    engine = SecurityEngine(replace(SecurityConfig(), max_ips=1), SECRET, clock=clock, wall_clock=clock)
    assert engine.screen_request(SecurityRequest('10.0.0.1', path='/health', raw_path='/health')).allow
    result = engine.screen_request(SecurityRequest('10.0.0.2', path='/health', raw_path='/health'))
    assert (result.status, result.reason) == (503, 'state_capacity')

def test_oversized_claim_is_rejected(setup):
    engine, clock = setup
    assert engine.screen_request(req(token(clock, sub='x'*257))).reason == 'bad_claims'

@pytest.mark.parametrize('bad', [float('nan'), float('inf')])
def test_nonfinite_claim_is_rejected(setup, bad):
    engine, clock = setup
    assert engine.screen_request(req(token(clock, exp=bad))).reason == 'bad_claims'

def test_suspicious_nested_list_is_scored(setup):
    engine, clock = setup
    r = req(token(clock), method='POST', headers={'authorization':'Bearer '+token(clock), 'content-type':'application/json'}, body=b'{"values":["union select"]}')
    assert engine.screen_request(r).reason == 'suspicious_pattern'

@pytest.mark.parametrize('name,value', [('SG_ISSUER',''), ('SG_MAX_CLAIM_BYTES','0'), ('SG_DECAY_PER_SECOND','nan'), ('SG_MAX_PATH_BYTES','-1')])
def test_additional_invalid_configuration(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        SecurityConfig.from_env()

def test_jwt_decode_error_is_rejected(setup, monkeypatch):
    engine, clock = setup
    def broken(*args, **kwargs):
        raise jwt.exceptions.DecodeError('invalid payload')
    monkeypatch.setattr(jwt, 'decode', broken)
    assert engine.screen_request(req(token(clock))).reason == 'malformed_token'
