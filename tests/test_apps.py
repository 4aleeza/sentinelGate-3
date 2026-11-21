import httpx
import pytest
import time
import jwt
from gateway.security import SecurityEngine
from gateway.security_config import SecurityConfig

from backend.app import app as backend
from gateway.app import app as gateway, strip_hop

SECRET = 'test-only-secret-0123456789abcdef0123456789'

@pytest.fixture(autouse=True)
def security_engine():
    gateway.state.security = SecurityEngine(SecurityConfig(), SECRET)

@pytest.fixture
def auth():
    now = int(time.time())
    token = jwt.encode({'sub': 'test', 'exp': now + 300, 'iat': now, 'iss': 'sentinelgate-lab', 'aud': 'sentinelgate-api', 'scope': 'api:read api:write'}, SECRET, algorithm='HS256')
    return {'authorization': 'Bearer ' + token}


@pytest.mark.asyncio
async def test_backend():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=backend), base_url="http://test") as client:
        assert (await client.get('/health')).json()['service'] == 'backend'
        info = (await client.get('/api/info', headers={'x-request-id': 'abc'})).json()
        assert info['peer_host'] == '127.0.0.1' and info['x_request_id'] == 'abc'
        assert (await client.post('/api/echo', json={'x': 1})).json()['body'] == {'x': 1}
        assert (await client.post('/api/echo', content=b'x' * 65537)).status_code == 413
        assert (await client.get('/api/slow?ms=2001')).status_code == 422


@pytest.mark.asyncio
async def test_gateway_headers_and_health(auth):
    seen = []
    async def upstream(request):
        seen.append(request)
        return httpx.Response(200, headers={'connection': 'x-remove', 'x-remove': 'bad', 'x-ok': 'yes'}, json={'ok': True})
    gateway.state.client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    async with gateway.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway, client=('10.10.1.10', 1234)), base_url='http://test', headers=auth) as client:
        assert (await client.get('/health')).status_code == 200 and not seen
        response = await client.get('/api/info', headers={'connection': 'x-remove', 'x-remove': 'bad', 'x-forwarded-for': 'spoof', 'x-request-id': 'valid-id', 'host': 'evil'})
        assert response.status_code == 200 and 'x-remove' not in response.headers
        assert seen[0].headers['x-forwarded-for'] == '10.10.1.10'
        assert seen[0].headers['x-request-id'] == 'valid-id' and seen[0].headers['host'] != 'evil'
        assert 'x-remove' not in seen[0].headers
        await client.get('/api/info', headers={'x-request-id': 'invalid id'})
        assert seen[1].headers['x-request-id'] != 'invalid id'
        assert (await client.post('/api/echo', content=b'x' * 65537)).status_code == 413


@pytest.mark.asyncio
@pytest.mark.parametrize(('error', 'status'), [(httpx.ConnectError('failed'), 502), (httpx.ReadTimeout('late'), 504)])
async def test_gateway_errors(error, status, auth):
    def fail(request):
        raise error
    gateway.state.client = httpx.AsyncClient(transport=httpx.MockTransport(fail))
    async with gateway.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway), base_url='http://test', headers=auth) as client:
        assert (await client.get('/api/info')).status_code == status


def test_hop_headers():
    assert strip_hop(httpx.Headers({'Connection': 'x-private', 'x-private': 'x', 'te': 'trailers', 'x-ok': 'yes'})) == {'x-ok': 'yes'}

@pytest.mark.asyncio
async def test_gateway_rejects_missing_token_without_upstream():
    def fail(request):
        raise AssertionError('rejected request reached upstream')
    gateway.state.client = httpx.AsyncClient(transport=httpx.MockTransport(fail))
    async with gateway.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway), base_url='http://test') as client:
        response = await client.get('/api/info')
        assert response.status_code == 401
        assert response.json()['error'] == 'missing_token'
        assert response.headers['www-authenticate'] == 'Bearer'

@pytest.mark.asyncio
@pytest.mark.parametrize('secret', ['', 'short'])
async def test_startup_rejects_missing_or_short_secret(monkeypatch, secret):
    monkeypatch.setenv('SENTINELGATE_JWT_SECRET', secret)
    with pytest.raises(ValueError):
        async with gateway.router.lifespan_context(gateway):
            pass

@pytest.mark.asyncio
async def test_startup_logs_effective_config_without_secret(monkeypatch, caplog):
    import logging
    monkeypatch.setenv('SENTINELGATE_JWT_SECRET', SECRET)
    monkeypatch.setenv('SG_BUCKET_CAPACITY', '37')
    with caplog.at_level(logging.INFO, logger='sentinelgate.gateway'):
        async with gateway.router.lifespan_context(gateway):
            assert gateway.state.security.config.bucket_capacity == 37
    assert '"bucket_capacity": 37.0' in caplog.text
    assert '[redacted]' in caplog.text
    assert SECRET not in caplog.text

@pytest.mark.asyncio
async def test_head_is_screened_and_forwarded(auth):
    seen = []
    def upstream(request):
        seen.append(request.method)
        return httpx.Response(200)
    gateway.state.client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    async with gateway.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway), base_url='http://test') as client:
        assert (await client.head('/api/info')).status_code == 401
        assert (await client.head('/api/info', headers=auth)).status_code == 200
    assert seen == ['HEAD']

@pytest.mark.asyncio
async def test_startup_logs_every_effective_override(monkeypatch, caplog):
    import json
    import logging
    from dataclasses import asdict
    defaults = asdict(SecurityConfig())
    monkeypatch.setenv('SENTINELGATE_JWT_SECRET', SECRET)
    for name, value in defaults.items():
        monkeypatch.setenv('SG_' + name.upper(), str(value))
    with caplog.at_level(logging.INFO, logger='sentinelgate.gateway'):
        async with gateway.router.lifespan_context(gateway):
            pass
    records = [json.loads(record.message) for record in caplog.records if record.message.startswith('{')]
    event = next(record for record in records if record.get('event') == 'security_config')
    assert event['config'] == defaults
    assert event['secret'] == '[redacted]'
    assert SECRET not in caplog.text
