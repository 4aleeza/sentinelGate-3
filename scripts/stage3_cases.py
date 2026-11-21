"""Run the predefined cases from sg-client; credentials remain in memory."""
import csv, json, os, shlex, subprocess, time, uuid
from datetime import datetime, timezone
from pathlib import Path
import httpx
from mint_token import mint

ROOT = Path('/work')
CASES = json.loads((ROOT/'tests/security_cases.json').read_text())
SECRET = os.environ['SENTINELGATE_JWT_SECRET']
TOKENS = {name: mint(name, SECRET) for name in ('valid','expired','wrong-signature','none','wrong-audience','insufficient-scope')}
GATEWAY_LOG = ROOT/'evidence/logs/gateway.log'
BACKEND_LOG = ROOT/'evidence/logs/backend.log'
rows = []
capture = None
windows = {}

def entries(path):
    result=[]
    for line in path.read_text(errors='replace').splitlines():
        try:
            item=json.loads(line)
            if isinstance(item,dict): result.append(item)
        except ValueError: pass
    return result

def request(ip, variant='valid', method='GET', path='/api/info', body=None, extra=None):
    request_id=uuid.uuid4().hex
    headers={'X-Request-ID':request_id}
    if variant is not None: headers['Authorization']='Bearer '+TOKENS[variant]
    if extra: headers.update(extra)
    before=len([e for e in entries(BACKEND_LOG) if e.get('request_id')])
    transport=httpx.HTTPTransport(local_address=ip, retries=0)
    started=datetime.now(timezone.utc).isoformat()
    with httpx.Client(transport=transport, timeout=10, trust_env=False) as client:
        response=client.request(method, 'http://10.10.3.10:8000'+path, headers=headers, content=body)
    time.sleep(.05)
    decisions=[e for e in entries(GATEWAY_LOG) if e.get('request_id') == request_id and 'decision' in e]
    backend=[e for e in entries(BACKEND_LOG) if e.get('request_id')]
    if not decisions: raise RuntimeError('Missing gateway decision for request '+request_id)
    d=decisions[-1]
    return {'utc':started, 'request_id':request_id, 'status':response.status_code, 'reason':d['reason'],
            'score_before':d['score_before'], 'score_after':d['score_after'], 'client_ip':d['client_ip'],
            'backend_before':before, 'backend_after':len(backend),
            'backend_reached':any(e.get('request_id') == request_id for e in backend),
            'retry_after':response.headers.get('retry-after',''), 'tier':d['tier']}

def persist():
    if not rows: return
    with (ROOT/'evidence/logs/stage3_cases.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    with (ROOT/'evidence/logs/stage3_cases_summary.txt').open('w') as f:
        f.write('COMMAND: ip netns exec sg-client python scripts/stage3_cases.py\n')
        f.write('UTC: '+datetime.now(timezone.utc).isoformat()+'\n')
        for row in rows: f.write(json.dumps(row)+'\n')

try:
    capture_path = ROOT/'evidence/captures/stage3/backend-cases.pcapng'
    capture_log = (ROOT/'evidence/captures/stage3/capture.log').open('w')
    capture = subprocess.Popen(['ip','netns','exec','sg-gateway','tshark','-i','sg-g1','-f','tcp port 9000','-w',str(capture_path)], stdout=capture_log, stderr=subprocess.STDOUT)
    time.sleep(2)
    if capture.poll() is not None: raise RuntimeError('Backend capture failed to start; inspect capture.log')
    for case in CASES:
        cid=case['id']; ip=case['source_ip']; spec=case['request']; variant=spec['headers'].get('authorization')
        if cid=='SC-11':
            for _ in range(20): request(ip)
        elif cid in ('SC-12','SC-13'):
            for _ in range(4): request(ip, 'wrong-signature')
            if cid=='SC-13':
                banned=request(ip)
                print('SC-13 ban observation:',json.dumps(banned), flush=True)
                time.sleep(int(banned['retry_after'] or '10')+1)
        elif cid=='SC-14':
            for _ in range(3): request(ip, 'wrong-signature')
            time.sleep(45)
        if cid == 'SC-15':
            spoof=request(ip, None, extra={'x-forwarded-for':'198.51.100.99'})
            print('SC-15 spoofed rejection:',json.dumps(spoof),flush=True)
            if spoof['client_ip'] != ip or spoof['reason'] != 'missing_token': raise RuntimeError('Spoof identity or scoring check failed')
        body=spec['body']
        if isinstance(body,dict): body=(body['repeat']*body['count']).encode()
        elif isinstance(body,str): body=body.encode()
        extra={k:v for k,v in spec['headers'].items() if k != 'authorization' and v is not None}
        window_start=time.time()
        result=request(ip, variant, spec['method'], spec['path'], body, extra)
        windows[cid]=(window_start,time.time())
        if cid == 'SC-04':
            capture.terminate(); capture.wait(timeout=10); capture_log.close(); capture=None
            fields=['frame.time','ip.src','ip.dst','tcp.srcport','tcp.dstport','tcp.stream','tcp.flags','http.request.method','http.request.uri','http.response.code']
            cmd=['tshark','-r',str(capture_path),'-T','fields','-E','header=y']
            for field in fields: cmd.extend(['-e',field])
            summary=subprocess.run(cmd, capture_output=True, text=True, check=True)
            outfile=ROOT/'evidence/captures/stage3/summary.txt'
            outfile.write_text('COMMAND: '+ shlex.join(cmd)+'\nUTC: '+datetime.now(timezone.utc).isoformat()+'\n'+summary.stdout+summary.stderr)
            counts={}
            for name in ('SC-01','SC-04'):
                start,end=windows[name]
                expr=f'frame.time_epoch >= {start} && frame.time_epoch <= {end} && ip.dst == 10.10.4.10 && tcp.dstport == 9000'
                check=['tshark','-r',str(capture_path),'-Y',expr,'-T','fields','-e','frame.number']
                counts[name]=len(subprocess.run(check,capture_output=True,text=True,check=True).stdout.splitlines())
                with outfile.open('a') as f: f.write('COMMAND: '+shlex.join(check)+'\n'+name+' packet count: '+str(counts[name])+'\n')
            if counts['SC-04'] or not counts['SC-01']: raise RuntimeError('Capture did not prove rejected versus allowed traffic')
        actual=(result['status'],result['reason'],result['backend_reached'])
        expected=(case['expected_status'],case['expected_reason'],case['backend_reached'])
        row={'case':cid, 'command':'ip netns exec sg-client python scripts/stage3_cases.py', 'source_ip':ip,
             'expected_status':expected[0], 'expected_reason':expected[1], 'expected_backend':expected[2],
             **result, 'pass':actual==expected and result['client_ip']==ip}
        rows.append(row); persist(); print(json.dumps(row),flush=True)
    if not all(row['pass'] for row in rows): raise RuntimeError('One or more case results differ from expected values')
    scan_path=ROOT/'evidence/logs/stage3_secret_scan.txt'
    needles=[SECRET.encode()] + [token.encode() for token in TOKENS.values()]
    affected=[]
    for value in needles:
        result=subprocess.run([b'grep',b'-rFl',b'--',value,b'.'],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if result.returncode not in (0,1): raise RuntimeError('Credential grep failed: '+result.stderr.decode(errors='replace'))
        affected.extend(result.stdout.decode(errors='replace').splitlines())
    scan_path.write_text('COMMAND: grep -rFl -- "$credential" . (each in-memory run secret and minted token; contents suppressed)\nUTC: '+datetime.now(timezone.utc).isoformat()+'\n'+('FAIL affected paths: '+', '.join(sorted(set(affected))) if affected else 'PASS: run secret and all minted token strings absent from project files')+'\n')
    if affected: raise RuntimeError('Run credential detected; see stage3_secret_scan.txt')
finally:
    if capture is not None:
        capture.terminate(); capture.wait(timeout=10)
    persist()