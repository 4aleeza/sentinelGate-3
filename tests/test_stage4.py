import json
import time
import httpx
import jwt
import pytest
from gateway.app import app
from gateway.observability import Observability, BUCKETS
from gateway.security import SecurityEngine
from gateway.security_config import SecurityConfig

SECRET='stage4-test-secret-0123456789abcdef-32'

def token(scope):
    now=int(time.time())
    return jwt.encode({'sub':'test','iat':now,'exp':now+300,'iss':'sentinelgate-lab','aud':'sentinelgate-api','scope':scope},SECRET,algorithm='HS256')

@pytest.fixture(autouse=True)
def state():
    app.state.security=SecurityEngine(SecurityConfig(),SECRET)
    app.state.observability=Observability()

@pytest.mark.asyncio
async def test_scope_separation_and_no_monitor_backend():
    seen=[]
    def upstream(req):
        seen.append(req.url.path); return httpx.Response(200,json={'ok':True})
    app.state.client=httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    async with app.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('10.0.0.1',123)),base_url='http://test') as client:
        mon={'Authorization':'Bearer '+token('monitor:read')}; api={'Authorization':'Bearer '+token('api:read api:write')}
        assert (await client.get('/monitor/summary')).status_code==401
        assert (await client.get('/monitor/summary',headers=api)).status_code==403
        assert (await client.post('/monitor/summary',headers=mon)).status_code==405
        assert (await client.get('/api/info',headers=mon)).status_code==403
        assert (await client.get('/monitor/summary',headers=mon)).status_code==200
        assert (await client.get('/monitor/ips',headers=mon)).status_code==200
        assert (await client.get('/monitor/events',headers=mon)).status_code==200
        assert seen==[]
        assert (await client.get('/api/info',headers=api)).status_code==200
        assert seen==['/api/info']
    st=app.state.observability
    assert st.total_requests==8 and st.monitor_requests==6 and st.api_requests==2
    assert st.allowed==4 and st.rejected==4
    assert st.reasons['missing_token']==1 and st.reasons['insufficient_scope']==2 and st.reasons['bad_method']==1
    assert st.statuses['401']==1 and st.statuses['403']==2 and st.statuses['405']==1 and st.statuses['200']==4

@pytest.mark.asyncio
async def test_monitor_never_exposes_secret_or_token():
    bearer=token('monitor:read'); headers={'Authorization':'Bearer '+bearer,'X-Request-ID':bearer}
    app.state.client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(AssertionError('upstream called'))))
    async with app.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        await client.get('/api/'+SECRET,headers=headers)
        for name in ('summary','ips','events'):
            result=await client.get('/monitor/'+name,headers=headers)
            assert result.status_code==200
            assert SECRET not in result.text and bearer not in result.text and 'Authorization' not in result.text
            assert SECRET not in str(result.headers) and bearer not in str(result.headers)
    assert SECRET not in json.dumps(list(app.state.observability.events))
    assert bearer not in json.dumps(list(app.state.observability.events))

@pytest.mark.asyncio
async def test_top_twenty_and_read_only_snapshot():
    store=app.state.security.store
    for i in range(25):
        state=store.get('10.1.0.'+str(i+1)); state.score=i
    before={ip:(s.tokens,s.score,s.last_seen) for ip,s in store.clients.items()}
    headers={'Authorization':'Bearer '+token('monitor:read')}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('10.2.0.1',1)),base_url='http://test') as client:
        payload=(await client.get('/monitor/ips',headers=headers)).json()
    assert len(payload['ips'])==20
    scores=[entry['score'] for entry in payload['ips']]
    assert scores==sorted(scores,reverse=True)
    assert all((store.clients[ip].tokens,store.clients[ip].score,store.clients[ip].last_seen)==value for ip,value in before.items())

def test_bounded_events_and_bucket_edges():
    stats=Observability(clock=lambda: 10)
    for i in range(205):
        stats.record(request_id=str(i),client_ip='10.0.0.1',method='GET',path='/api/info',decision='allow',reason='allowed',status=200,score_after=0,tier='normal',latency_ms=10 if i==0 else 25)
    assert len(stats.events)==200 and stats.events[0]['request_id']=='5' and stats.events[-1]['request_id']=='204'
    assert stats.latency_count==205 and stats.buckets['10']==1 and stats.buckets['25']==205 and stats.buckets['+Inf']==205
    assert set(stats.buckets)=={str(x) for x in BUCKETS}|{'+Inf'}
@pytest.mark.parametrize('bound', BUCKETS)
def test_latency_bucket_edges(bound):
    stats=Observability(clock=lambda:0)
    for value in (bound, bound+0.001):
        stats.record(request_id='x',client_ip='1.2.3.4',method='GET',path='/health',decision='allow',reason='allowed',status=200,score_after=0,tier='normal',latency_ms=value)
    assert stats.buckets[str(bound)]==1
    assert stats.buckets['+Inf']==2 and stats.latency_count==2
    assert stats.latency_sum_ms==pytest.approx(2*bound+0.001) and stats.latency_max_ms==bound+0.001

def test_fake_clock_ban_lifecycle():
    class Clock:
        t=100
        def __call__(self): return self.t
    clock=Clock(); engine=SecurityEngine(SecurityConfig(),SECRET,clock=clock)
    state=engine.store.get('10.0.0.1')
    for _ in range(4): engine.store.record(state,'bad_signature')
    assert engine.store.bans_issued==1 and engine.store.ban_expiries==0
    clock.t+=31; engine.store.get('10.0.0.1')
    assert engine.store.ban_expiries==1 and state.score==pytest.approx(29.5)
    engine.store.get('10.0.0.1'); assert engine.store.ban_expiries==1

@pytest.mark.asyncio
async def test_upstream_failure_is_counted_once():
    def fail(req): raise httpx.ConnectError('offline')
    app.state.client=httpx.AsyncClient(transport=httpx.MockTransport(fail))
    async with app.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        result=await client.get('/api/info',headers={'Authorization':'Bearer '+token('api:read')})
    assert result.status_code==502
    stats=app.state.observability
    assert stats.total_requests==1 and stats.upstream_errors==1 and stats.statuses['502']==1
    assert set(stats.events[0])=={'timestamp','request_id','client_ip','method','path','decision','reason','status','score_after','tier'}

@pytest.mark.asyncio
@pytest.mark.parametrize(('supplied','valid'), [('abc.def.ghi',False), ('a'*65,False), ('',False), ('valid-123',True)])
async def test_request_id_format(supplied, valid):
    seen=[]
    def upstream(req):
        seen.append(req.headers['x-request-id'])
        return httpx.Response(200)
    app.state.client=httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    async with app.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        response=await client.get('/api/info',headers={'Authorization':'Bearer '+token('api:read'),'X-Request-ID':supplied})
    assert response.status_code == 200
    assert response.headers['x-request-id'] == seen[0]
    assert (seen[0] == supplied) is valid
    assert 8 <= len(seen[0]) <= 64 and all(c.isalnum() or c == '-' for c in seen[0])

@pytest.mark.asyncio
async def test_monitor_redacts_secret_in_config():
    from dataclasses import replace
    app.state.security.config = replace(app.state.security.config, issuer=SECRET)
    now=int(time.time())
    bearer=jwt.encode({'sub':'test','iat':now,'exp':now+300,'iss':SECRET,'aud':'sentinelgate-api','scope':'monitor:read'},SECRET,algorithm='HS256')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        response=await client.get('/monitor/summary',headers={'Authorization':'Bearer '+bearer})
    assert response.status_code == 200
    assert response.json()['thresholds']['issuer'] == '[redacted]'
    assert SECRET not in response.text

@pytest.mark.asyncio
@pytest.mark.parametrize(('error','status','result'), [(httpx.ConnectError('offline'),502,'connect_error'),(httpx.ReadTimeout('late'),504,'timeout')])
async def test_final_outcome_upstream_errors(error,status,result,caplog):
    def fail(req): raise error
    app.state.client=httpx.AsyncClient(transport=httpx.MockTransport(fail))
    with caplog.at_level('INFO', logger='sentinelgate.gateway'):
        async with app.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
            response=await client.get('/api/info',headers={'Authorization':'Bearer '+token('api:read'),'X-Request-ID':'request-123'})
    outcomes=[json.loads(r.message) for r in caplog.records if r.message.startswith('{') and json.loads(r.message).get('event')=='final_outcome']
    assert response.status_code == status and len(outcomes)==1
    assert outcomes[0]['status']==status and outcomes[0]['upstream_result']==result
    assert outcomes[0]['request_id']=='request-123' and outcomes[0]['upstream_latency_ms'] >= 0
    assert app.state.observability.api_latency['count']==1

@pytest.mark.asyncio
async def test_final_outcomes_for_rejection_and_success(caplog):
    app.state.client=httpx.AsyncClient(transport=httpx.MockTransport(lambda req:httpx.Response(200)))
    with caplog.at_level('INFO', logger='sentinelgate.gateway'):
        async with app.state.client, httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
            await client.get('/api/info')
            await client.get('/api/info',headers={'Authorization':'Bearer '+token('api:read')})
            summary=await client.get('/monitor/summary',headers={'Authorization':'Bearer '+token('monitor:read')})
    outcomes=[json.loads(r.message) for r in caplog.records if r.message.startswith('{') and json.loads(r.message).get('event')=='final_outcome']
    assert [(x['status'],x['upstream_result']) for x in outcomes]==[(401,'not_forwarded'),(200,'ok'),(200,'not_forwarded')]
    assert summary.json()['api_latency_ms']['count']==2
    assert summary.json()['latency_ms']['count']==2
    assert app.state.observability.latency_count==3 and app.state.observability.api_latency['count']==2
