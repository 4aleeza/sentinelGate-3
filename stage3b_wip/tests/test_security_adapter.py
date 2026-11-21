import pytest
import asyncio
from gateway.security_adapter import client_ip_from_asgi
from gateway.security_adapter import screen_request
from gateway.security import SecurityEngine
from gateway.security_config import SecurityConfig
from types import SimpleNamespace


def test_identity_is_asgi_peer_not_spoofed_forwarded_header():
    scope = {'client': ('10.10.1.25', 53214),
             'headers': [(b'x-forwarded-for', b'198.51.100.99')]}
    assert client_ip_from_asgi(scope) == '10.10.1.25'


@pytest.mark.parametrize('client', [None, (), ('', 5), ('x',), '10.0.0.1'])
def test_missing_or_malformed_asgi_peer_fails_closed(client):
    with pytest.raises(ValueError):
        client_ip_from_asgi({'client': client})


def test_banned_request_never_reads_body():
    engine = SecurityEngine(SecurityConfig(), 'test-secret-at-least-32-bytes-long', clock=lambda: 1000, wall_clock=lambda: 1000)
    state = engine.store.get('10.10.1.25')
    engine.store.record(state, 'bad_algorithm'); engine.store.record(state, 'bad_algorithm')
    class Request:
        scope = {'client': ('10.10.1.25', 1234), 'headers': [(b'x-forwarded-for', b'198.51.100.99')]}
        url = SimpleNamespace(path='/api/echo')
        state = SimpleNamespace(request_id='test')
        method = 'POST'
        headers = {}
        async def stream(self):
            raise AssertionError('banned requests must not read a body')
            yield b''
    decision, body = asyncio.run(screen_request(Request(), engine))
    assert decision.reason == 'banned' and decision.client_ip == '10.10.1.25' and body == b''
