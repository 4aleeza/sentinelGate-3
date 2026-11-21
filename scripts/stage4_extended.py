import csv, json, os, signal, subprocess, time, uuid
from pathlib import Path
import httpx
from mint_token import mint
root=Path('/work'); logs=root/'evidence/logs'; secret=os.environ['SENTINELGATE_JWT_SECRET']
tokens={x:os.environ['SG_RUN_TOKEN_'+x.upper().replace('-','_')] for x in ('valid','monitor','wrong-signature')}
def req(ip,path,variant):
    rid=uuid.uuid4().hex
    with httpx.Client(transport=httpx.HTTPTransport(local_address=ip),timeout=10,trust_env=False) as c:
        r=c.get('http://10.10.3.10:8000'+path,headers={'Authorization':'Bearer '+tokens[variant],'X-Request-ID':rid})
    return r,rid
def summary():
    r,_=req('10.10.1.16','/monitor/summary','monitor'); r.raise_for_status(); return r.json(),_
def records():
    out=[]
    for line in (logs/'gateway.log').read_text(errors='replace').splitlines():
        try:
            obj=json.loads(line)
            if 'decision' in obj or obj.get('event')=='final_outcome': out.append(obj)
        except ValueError: pass
    return out
expected={'ban_starts':1,'ban_expiries':1,'upstream_errors':1,'outage_status':'502 or 504','ban_bad_signature_requests':4,'post_expiry_requests':1,'outage_requests':1,'latency_count':8,'latency_api_decisions':7,'latency_baseline_monitor_decisions':1,'final_status_200':2,'final_status_401':3,'final_status_403':2,'final_status_502':1}
(logs/'stage4_extended_expected.json').write_text(json.dumps(expected,indent=2))
base,base_id=summary(); ids=[]
for _ in range(4):
    r,rid=req('10.10.1.21','/api/info','wrong-signature'); ids.append(rid)
r,rid=req('10.10.1.21','/api/info','valid'); ids.append(rid)
retry=int(r.headers.get('Retry-After','0')); ban_status=r.status_code
time.sleep(retry+1)
r,rid=req('10.10.1.21','/api/info','valid'); ids.append(rid); expiry_status=r.status_code
pidfile=logs/'backend.pid'; pid=int(pidfile.read_text()); os.kill(pid,signal.SIGTERM)
for _ in range(100):
    if subprocess.run(['ip','netns','exec','sg-backend','ss','-ltnH','sport = :9000'],capture_output=True,text=True).stdout.strip()=='': break
    time.sleep(.1)
else: raise RuntimeError('backend did not stop')
try:
    r,outage_id=req('10.10.1.22','/api/info','valid'); ids.append(outage_id); outage_status=r.status_code
finally:
    with (logs/'backend.log').open('a') as f:
        proc=subprocess.Popen(['ip','netns','exec','sg-backend','/opt/venv/bin/uvicorn','backend.app:app','--host','10.10.4.10','--port','9000','--no-proxy-headers','--forwarded-allow-ips','','--workers','1'],stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
    pidfile.write_text(str(proc.pid)+'\n')
    for _ in range(100):
        if subprocess.run(['ip','netns','exec','sg-backend','ss','-ltnH','sport = :9000'],capture_output=True,text=True).stdout.strip(): break
        time.sleep(.1)
    else: raise RuntimeError('backend failed to restart')
after,_=summary(); all_records=records(); events=[x for x in all_records if x.get('request_id') in ids and 'decision' in x]; finals=[x for x in all_records if x.get('request_id') in ids+[base_id] and x.get('event')=='final_outcome']
ban_events=[x for x in events if x.get('client_ip')=='10.10.1.21']
starts=sum(1 for x in ban_events if x.get('score_before',0)<70 and x.get('score_after',0)>=70)
expiries=int(ban_status==403 and expiry_status==200 and any(x.get('request_id')==ids[-2] and x.get('reason')=='allowed' for x in events))
bounds=['10','25','50','100','250','500','1000','2500','+Inf']; delta=[after['latency_ms']['buckets'][b]-base['latency_ms']['buckets'][b] for b in bounds]
intervals=[delta[0]]+[delta[i]-delta[i-1] for i in range(1,len(delta))]
rows=[]
def row(name,want,actual,derived,note=''):
    rows.append({'counter':name,'expected':want,'observed':actual,'log_derived':derived,'note':note})
row('bans_issued',1,after['bans_issued']-base['bans_issued'],starts)
row('ban_expiries',1,after['ban_expiries']-base['ban_expiries'],expiries,'inferred from banned then allowed decision after wait')
outage_decision=next((x for x in finals if x.get('request_id')==outage_id),{})
row('upstream_errors',1,after['upstream_errors']-base['upstream_errors'],sum(x['status'] in (502,504) for x in finals),'final-outcome records; client observed '+str(outage_status))
row('latency_count',len(ids)+1,after['latency_ms']['count']-base['latency_ms']['count'],len(events)+1,'includes baseline summary after its snapshot')
row('latency_interval_sum',len(ids)+1,sum(intervals),len(events)+1,'intervals derived from cumulative bucket differences; includes baseline summary')
row('api_latency_count',7,after['api_latency_ms']['count']-base['api_latency_ms']['count'],sum(x['path'].startswith('/api/') for x in finals))
api_delta=[after['api_latency_ms']['buckets'][b]-base['api_latency_ms']['buckets'][b] for b in bounds]
api_intervals=[api_delta[0]]+[api_delta[i]-api_delta[i-1] for i in range(1,len(api_delta))]
row('api_latency_interval_sum',7,sum(api_intervals),sum(x['path'].startswith('/api/') for x in finals))
for status,want in [(200,expected['final_status_200']),(401,expected['final_status_401']),(403,expected['final_status_403']),(502,expected['final_status_502'])]:
    row('final_status_'+str(status),want,after['statuses'].get(str(status),0)-base['statuses'].get(str(status),0),sum(x['status']==status for x in finals))
for b,c,n in zip(bounds,delta,intervals): row('latency_bucket_le_'+b,'',c,'','exclusive interval='+str(n))
for b,c,n in zip(bounds,api_delta,api_intervals): row('api_latency_bucket_le_'+b,'',c,'','exclusive interval='+str(n))
with (logs/'stage4_extended_comparison.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['counter','expected','observed','log_derived','note']);w.writeheader();w.writerows(rows)
(logs/'stage4_extended_outcomes.json').write_text(json.dumps({'request_ids':ids,'ban_status':ban_status,'retry_after':retry,'post_expiry_status':expiry_status,'outage_status':outage_status,'outage_decision':outage_decision,'exclusive_intervals':dict(zip(bounds,intervals))},indent=2))
if ban_status!=403 or expiry_status!=200 or outage_status not in (502,504) or any(str(x['expected'])!=str(x['observed']) or str(x['expected'])!=str(x['log_derived']) for x in rows if x['expected'] != ''):
    raise RuntimeError('extended comparison mismatch; see stage4_extended_comparison.csv')
