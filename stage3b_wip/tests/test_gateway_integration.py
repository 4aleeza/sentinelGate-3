import asyncio
import os
import time
import httpx
import jwt
from gateway.app import app

SECRET = 'temporary-test-secret-at-least-32-bytes'

def test_asgi_peer_is_forwarded_and_rejects_before_upstream():
    async def run():
        old = os.environ.get('SENTINELGATE_JWT_SECRET')
        os.environ['SENTINELGATE_JWT_SECRET'] = SECRET
        try:
            async with app.router.lifespan_context(app):
                calls = []
                async def backend(request):
                    calls.append(request)
                    return httpx.Response(200, json={'ok': True})
                async with httpx.AsyncClient(transport=httpx.MockTransport(backend)) as upstream:
                    app.state.client = upstream
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('10.10.1.25', 1234)), base_url='http://test') as client:
                        denied = await client.get('/api/info', headers={'x-forwarded-for':'198.51.100.99'})
                        assert denied.status_code == 401 and denied.json()['error'] == 'missing_token' and not calls
                        now = time.time()
                        token = jwt.encode({'sub':'test','iat':now,'exp':now+60,'iss':'sentinelgate-lab','aud':'sentinelgate-api','scope':'api:read'}, SECRET, algorithm='HS256')
                        allowed = await client.get('/api/info', headers={'authorization':'Bearer '+token, 'x-forwarded-for':'198.51.100.99'})
                        assert allowed.status_code == 200 and calls[0].headers['x-forwarded-for'] == '10.10.1.25'
                        assert '198.51.100.99' not in app.state.security.store.clients
        finally:
            if old is None: os.environ.pop('SENTINELGATE_JWT_SECRET', None)
            else: os.environ['SENTINELGATE_JWT_SECRET'] = old
    asyncio.run(run())
