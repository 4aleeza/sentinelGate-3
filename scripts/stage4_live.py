"""Stage 4 live measurements; no credentials are written to evidence."""
import collections, csv, json, os, subprocess, time, uuid
from datetime import datetime, timezone
from pathlib import Path
import httpx
from mint_token import mint

root=Path('/work'); logs=root/'evidence/logs'; secret=os.environ['SENTINELGATE_JWT_SECRET']
tokens={name:os.environ['SG_RUN_TOKEN_'+name.upper().replace('-','_')] for name in ('valid','monitor','wrong-signature')}
expected={'total_requests':42,'api_requests':41,'monitor_requests':0,'allowed':31,'rejected':11,'rate_limited':5,
          'reason:allowed':31,'reason:missing_token':3,'reason:bad_signature':2,'reason:bad_path':1,'reason:rate_limited':5,
          'status:200':31,'status:401':5,'status:400':1,'status:429':5}
(logs/'stage4_expected.json').write_text(json.dumps({'command':'ip netns exec sg-client python scripts/stage4_live.py','utc':datetime.now(timezone.utc).isoformat(),'expected_before_sequence':expected},indent=2))

def request(source,path,variant='valid',method='GET'):
    headers={'X-Request-ID':uuid.uuid4().hex}
    if variant: headers['Authorization']='Bearer '+tokens[variant]
    with httpx.Client(transport=httpx.HTTPTransport(local_address=source),timeout=10,trust_env=False) as client:
        response=client.request(method,'http://10.10.3.10:8000'+path,headers=headers)
    return response,headers['X-Request-ID']

results=[]
for source, path, variant, count in [('10.10.1.11','/api/info','valid',10),('10.10.1.12','/api/info',None,3),('10.10.1.13','/api/info','wrong-signature',2),('10.10.1.14','/api/%2e%2e/info','valid',1),('10.10.1.15','/api/info','valid',25)]:
    for _ in range(count):
        response,rid=request(source,path,variant)
        results.append({'source':source,'path':path,'variant':variant,'status':response.status_code,'request_id':rid})
(logs/'stage4_sequence.json').write_text(json.dumps(results,indent=2))
summary,rid=request('10.10.1.16','/monitor/summary','monitor')
if summary.status_code!=200: raise RuntimeError('Summary request failed: '+str(summary.status_code))
summary=summary.json(); (logs/'stage4_summary.json').write_text(json.dumps(summary,indent=2))
entries=[]
finals=[]
for line in (logs/'gateway.log').read_text(errors='replace').splitlines():
    try:
        obj=json.loads(line)
        if 'decision' in obj and obj.get('request_id')!=rid: entries.append(obj)
        if obj.get('event')=='final_outcome' and obj.get('request_id')!=rid: finals.append(obj)
    except ValueError: pass
reason=collections.Counter(item['reason'] for item in entries); statuses=collections.Counter(str(item['status']) for item in finals)
derived={'total_requests':len(entries),'api_requests':sum(item['path'].startswith('/api/') for item in entries),
         'monitor_requests':sum(item['path'].startswith('/monitor/') for item in entries),
         'allowed':sum(item['decision']=='allow' for item in entries),'rejected':sum(item['decision']=='reject' for item in entries),
         'rate_limited':reason['rate_limited']}
for key in expected:
    if key.startswith('reason:'): derived[key]=reason[key.split(':',1)[1]]
    if key.startswith('status:'): derived[key]=statuses[key.split(':',1)[1]]
def observed(key):
    if key.startswith('reason:'): return summary['reasons'].get(key.split(':',1)[1],0)
    if key.startswith('status:'): return summary['statuses'].get(key.split(':',1)[1],0)
    return summary[key]
table=[{'counter':key,'expected':value,'observed':observed(key),'log_derived':derived[key]} for key,value in expected.items()]
with (logs/'stage4_counter_comparison.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['counter','expected','observed','log_derived']);w.writeheader();w.writerows(table)
mismatches=[row for row in table if row['expected']!=row['observed'] or row['expected']!=row['log_derived']]
ips1,_=request('10.10.1.16','/monitor/ips','monitor'); events,_=request('10.10.1.16','/monitor/events','monitor'); _,_=request('10.10.1.16','/monitor/summary','monitor'); ips2,_=request('10.10.1.16','/monitor/ips','monitor')
if any(response.status_code!=200 for response in (ips1,events,ips2)): raise RuntimeError('Monitoring snapshot request failed')
(logs/'stage4_events.json').write_text(json.dumps(events.json(),indent=2))
a={x['ip']:x for x in ips1.json()['ips']}; b={x['ip']:x for x in ips2.json()['ips']}; others=set(a)|set(b); others.discard('10.10.1.16')
changes=[]
for ip in sorted(others):
    if ip not in a or ip not in b: changes.append({'ip':ip,'issue':'membership changed'})
    elif b[ip]['score']>a[ip]['score']+1e-6 or b[ip]['tier']!=a[ip]['tier'] or b[ip]['ban_remaining']!=a[ip]['ban_remaining']:
        changes.append({'ip':ip,'before':a[ip],'after':b[ip]})
(logs/'stage4_readonly.json').write_text(json.dumps({'before':ips1.json(),'after':ips2.json(),'unexpected_changes':changes,'note':'Scores may decrease naturally with time; monitoring client consumes its own bucket.'},indent=2))
negative=[]
for src,path,variant,method,want in [('10.10.1.17','/monitor/summary',None,'GET',401),('10.10.1.18','/monitor/summary','valid','GET',403),('10.10.1.19','/monitor/summary','monitor','POST',405),('10.10.1.20','/api/info','monitor','GET',403)]:
    response,rid=request(src,path,variant,method); negative.append({'source':src,'path':path,'method':method,'variant':variant,'status':response.status_code,'expected':want,'request_id':rid})
(logs/'stage4_negative.json').write_text(json.dumps(negative,indent=2))
if mismatches or changes or any(x['status']!=x['expected'] for x in negative):
    raise RuntimeError('Verification mismatch; inspect comparison, readonly and negative files')
print('PASS: expected, monitor and independently log-derived counts agree; negative checks passed',flush=True)
