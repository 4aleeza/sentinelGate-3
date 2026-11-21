from dataclasses import replace
import pytest
from gateway.risk_state import CapacityError, RiskStore
from gateway.security_config import SecurityConfig


class Clock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    def advance(self, seconds): self.now += seconds


def test_bucket_refill_and_isolation():
    clock = Clock()
    store = RiskStore(SecurityConfig(), clock)
    a = store.get('a')
    for _ in range(20): assert store.take_token(a) == 0
    assert store.take_token(a) == 1
    assert store.take_token(store.get('b')) == 0
    clock.advance(0.1)
    assert store.take_token(store.get('a')) == 0


def test_ban_expiry_probation_and_escalation():
    clock = Clock()
    store = RiskStore(SecurityConfig(), clock)
    a = store.get('a')
    store.record(a, 'bad_algorithm')
    assert a.score == 40
    store.record(a, 'bad_algorithm')
    assert a.score == 80 and store.ban_remaining(a) == 30
    clock.advance(30)
    a = store.get('a')
    assert a.score == 30 and store.ban_remaining(a) == 0
    store.record(a, 'bad_algorithm')
    assert a.score == 70 and store.ban_remaining(a) == 60


def test_decay_and_capacity():
    clock = Clock()
    cfg = replace(SecurityConfig(), max_ips=1)
    store = RiskStore(cfg, clock)
    a = store.get('a')
    store.record(a, 'bad_signature')
    with pytest.raises(CapacityError): store.get('b')
    clock.advance(40)
    assert store.get('a').score == 0
    store.get('b')
    assert set(store.clients) == {'b'}


def test_elevated_capacity_and_refill_exact_threshold():
    clock = Clock(); store = RiskStore(replace(SecurityConfig(), decay_per_second=0), clock); state = store.get('a')
    store.record(state, 'bad_algorithm')
    assert state.score == 40
    state = store.get('a')
    for _ in range(10): assert store.take_token(state) == 0
    assert store.take_token(state) == 1
    clock.advance(0.1)
    assert store.take_token(store.get('a')) == 1
    assert abs(state.tokens - 0.5) < 1e-9
    clock.advance(0.1)
    assert store.take_token(store.get('a')) == 0


def test_score_clamp_decay_and_exact_ban_threshold():
    clock = Clock(); store = RiskStore(SecurityConfig(), clock); s = store.get('a')
    store.record(s, 'bad_algorithm'); store.record(s, 'bad_signature'); store.record(s, 'bad_claims')
    assert s.score == 70 and store.ban_remaining(s) == 30
    store.record(s, 'bad_algorithm'); assert s.score == 100
    clock.advance(30); s = store.get('a'); assert s.score == 30
    clock.advance(20); assert store.get('a').score == 20


def test_escalation_cap_and_offence_memory_reset():
    clock = Clock(); store = RiskStore(SecurityConfig(), clock); s = store.get('a')
    for expected in (30, 60, 120, 240, 240):
        store.record(s, 'bad_algorithm'); store.record(s, 'bad_algorithm')
        assert store.ban_remaining(s) == expected
        clock.advance(expected); s = store.get('a')
    clock.advance(601); s = store.get('a')
    store.record(s, 'bad_algorithm'); store.record(s, 'bad_algorithm')
    assert store.ban_remaining(s) == 30


def test_idle_evicts_oldest_and_expired():
    clock = Clock(); store = RiskStore(replace(SecurityConfig(), max_ips=2), clock)
    store.get('a'); clock.advance(1); store.get('b'); store.get('c')
    assert set(store.clients) == {'b','c'}
    clock.advance(901); store.get('d'); store.get('e'); store.get('f')
    assert len(store.clients) <= 2 and 'b' not in store.clients


@pytest.mark.parametrize('reason,points', [
    ('rate_limited',5),('missing_token',5),('malformed_token',10),('expired_token',5),
    ('bad_claims',10),('insufficient_scope',5),('bad_request',10),('bad_method',10),
    ('bad_path',10),('bad_content_type',10),('body_too_large',10),
    ('suspicious_pattern',15),('bad_signature',20),('bad_algorithm',40)])
def test_every_event_weight(reason, points):
    clock = Clock(); store = RiskStore(SecurityConfig(), clock); state = store.get('a')
    assert store.record(state, reason) == (0, points)


def test_full_active_table_refuses_new_ip():
    clock = Clock(); store = RiskStore(replace(SecurityConfig(), max_ips=1), clock)
    store.record(store.get('a'), 'bad_signature')
    with pytest.raises(CapacityError): store.get('b')
    assert list(store.clients) == ['a']
