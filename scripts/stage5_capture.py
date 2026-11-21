"""Capture Stage 5 evidence inside the isolated lab container."""
import csv, hashlib, json, os, shlex, signal, subprocess, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from mint_token import mint

root=Path('/work')
out=root/os.environ['STAGE5_DIR']
secret=os.environ['SENTINELGATE_JWT_SECRET']
tokens={name:mint(name,secret) for name in ('valid','wrong-signature','insufficient-scope')}
points={'P1':('sg-client','sg-c0'),'P2':('sg-r1','sg-r11'),'P3':('sg-gateway','sg-g0'),'P4':('sg-gateway','sg-g1')}
capture_filter='tcp port 8000 or tcp port 9000 or icmp'
decode=['-d','tcp.port==8000,http','-d','tcp.port==9000,http']
fields=['frame.number','frame.time_epoch','frame.len','frame.cap_len','ip.src','ip.dst','ip.ttl','ip.proto','icmp.type','icmp.code','tcp.srcport','tcp.dstport','tcp.stream','tcp.flags.str','tcp.seq','tcp.ack','http.request.method','http.request.uri','http.response.code','http.request.line']
def stamp(): return datetime.now(timezone.utc).isoformat()
def cmdtext(args): return shlex.join(str(x) for x in args)
def call(args,**kw): return subprocess.run([str(x) for x in args],text=True,**kw)
def version(binary):
    r=call([binary,'--version'],capture_output=True)
    return next((x for x in r.stdout.splitlines() if x.strip()), 'unavailable')
versions={name:version(name) for name in ('tshark','capinfos','dumpcap')}
manifest=[]
def textfile(path, command, content):
    path.write_text('UTC: '+stamp()+'\nCOMMAND: '+command+'\n'+content,encoding='utf-8')
def curl(ip,rid,variant='valid',path='/api/info',post=False):
    args=['ip','netns','exec','sg-client','curl','--noproxy','*','--interface',ip,'--max-time','8','--silent','--show-error','--include','--path-as-is','--header','X-Request-ID: '+rid]
    if variant: args+=['--header','Authorization: Bearer '+tokens[variant]]
    if post: args+=['--header','Content-Type: application/json','--data','{"message":"stage5"}']
    args+=['http://10.10.3.10:8000'+path]
    result=call(args,capture_output=True)
    safe=['Authorization: Bearer $LAB_TOKEN' if x.startswith('Authorization: Bearer ') else x for x in args]
    return 'COMMAND: '+cmdtext(safe)+'\nEXIT: '+str(result.returncode)+'\n'+result.stdout+result.stderr
def capture(case,ip,fn):
    folder=out/case;folder.mkdir()
    handles=[]; procs=[]
    for point,(ns,interface) in points.items():
        file=folder/(point+'.pcapng'); err=folder/(point+'_capture.log')
        args=['ip','netns','exec',ns,'dumpcap','-i',interface,'-s','262144','-f',capture_filter,'-w',str(file)]
        handle=err.open('w'); handle.write('UTC: '+stamp()+'\nCOMMAND: '+cmdtext(args)+'\n');handle.flush()
        proc=subprocess.Popen(args,stdout=handle,stderr=handle,start_new_session=True)
        handles.append(handle);procs.append((point,ns,interface,file,err,args,proc))
    for point,ns,interface,file,err,args,proc in procs:
        for _ in range(100):
            if proc.poll() is not None: raise RuntimeError(point+' capture exited early: '+err.read_text())
            if file.exists() and 'File:' in err.read_text(errors='replace'): break
            time.sleep(.1)
        else: raise RuntimeError(point+' capture did not become ready: '+err.read_text())
    started=stamp()
    try: fn(folder)
    finally:
        time.sleep(2)
        for *_,proc in procs:
            if proc.poll() is None: os.killpg(proc.pid,signal.SIGINT)
        for *_,proc in procs:
            try: proc.wait(timeout=12)
            except subprocess.TimeoutExpired: proc.kill();proc.wait()
        for h in handles: h.close()
    for point,ns,interface,file,err,args,proc in procs:
        info=call(['capinfos','-T','-c','-a','-e','-s','-l',file],capture_output=True)
        details=call(['capinfos',file],capture_output=True)
        query=['tshark','-r',file,*decode,'-T','fields','-E','header=y','-E','separator=,','-E','quote=d','-E','occurrence=a']
        for f in fields: query+=['-e',f]
        data=call(query,capture_output=True)
        textfile(folder/(point+'_summary.csv'),cmdtext(query),'DERIVED TEXT; stderr: '+data.stderr+'\n'+data.stdout)
        textfile(folder/(point+'_capinfos.txt'),cmdtext(['capinfos',file]),details.stdout+details.stderr+'\nEXIT: '+str(details.returncode))
        count=call(['tshark','-r',file,'-T','fields','-e','frame.number'],capture_output=True)
        count_value=len(count.stdout.splitlines())
        caplog=err.read_text(errors='replace')
        drop=next((line.strip() for line in caplog.splitlines() if 'drop' in line.lower()),'not reported by capture tool')
        manifest.append({'scenario':case,'point':point,'file':str(file.relative_to(root)),'interface':interface,'namespace':ns,'command':cmdtext(args),'snaplen_requested':262144,'capture_started_utc':started,'capture_ended_utc':stamp(),'packet_count':count_value,'drop_report':drop,'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'tshark':versions['tshark'],'capinfos':versions['capinfos'],'dumpcap':versions['dumpcap']})
        if info.returncode or data.returncode or count.returncode: raise RuntimeError('capture verification failed '+str(file))
    print(case,'captured',flush=True)
def one(case,ip,variant='valid',path='/api/info',post=False):
    rid='sg-'+case.lower()+'-'+uuid.uuid4().hex[:12]
    def run(folder): textfile(folder/'client.txt','curl output generated by commands below',curl(ip,rid,variant,path,post))
    capture(case,ip,run)
def p07(folder):
    rows=[]
    for i in range(1,31):
        rid='sg-p07-'+uuid.uuid4().hex[:12]
        result=curl('10.10.1.17',rid)
        rows.append(result)
        if ' 429 ' in result: break
    textfile(folder/'client.txt','curl burst until first HTTP 429','\n'.join(rows))
def p08(folder):
    rid='sg-p08-'+uuid.uuid4().hex[:12]
    textfile(folder/'client.txt','request while previously banned',curl('10.10.1.18',rid))
def p09(folder):
    cmds=[['ip','netns','exec','sg-client','ping','-I','10.10.1.19','-c','1','-W','2','10.10.4.10'],['ip','netns','exec','sg-client','curl','--noproxy','*','--interface','10.10.1.19','--max-time','3','-v','http://10.10.4.10:9000/health']]
    lines=[]
    for args in cmds:
        r=call(args,capture_output=True); lines.append('COMMAND: '+cmdtext(args)+'\nEXIT: '+str(r.returncode)+'\n'+r.stdout+r.stderr)
    textfile(folder/'client.txt','ping and curl direct to backend','\n'.join(lines))
def p10(folder):
    rid='sg-p10-'+uuid.uuid4().hex[:12]
    args=['ip','netns','exec','sg-client','curl','--noproxy','*','--interface','10.10.1.20','--max-time','8','--silent','--show-error','--include','--header','X-Request-ID: '+rid,'--header','Authorization: Bearer '+tokens['valid'],'http://10.10.3.10:8000/api/info','http://10.10.3.10:8000/api/info']
    r=call(args,capture_output=True);safe=['Authorization: Bearer $LAB_TOKEN' if x.startswith('Authorization: Bearer ') else x for x in args]
    textfile(folder/'client.txt',cmdtext(safe),'EXIT: '+str(r.returncode)+'\n'+r.stdout+r.stderr)
def routing():
    path=root/'evidence/routing/stage5'/(out.name+'.txt')
    commands=[]
    for ns in ['sg-client','sg-r1','sg-r2','sg-gateway','sg-backend']:
        for suffix in (['ip','-br','addr'],['ip','route'],['ip','rule'],['sysctl','net.ipv4.ip_forward'],['ip','neigh']):
            commands.append(['ip','netns','exec',ns,*suffix])
    for suffix in (['ip','route','get','10.10.3.10'],['ip','route','get','10.10.4.10'],['ping','-c','2','-W','2','10.10.3.10'],['traceroute','-n','-q','1','-w','1','10.10.3.10'],['traceroute','-I','-n','-q','1','-w','1','10.10.3.10']):
        commands.append(['ip','netns','exec','sg-client',*suffix])
    with path.open('w') as f:
        f.write('UTC: '+stamp()+'\n')
        for args in commands:
            r=call(args,capture_output=True)
            f.write('COMMAND: '+cmdtext(args)+'\nEXIT: '+str(r.returncode)+'\n'+r.stdout+r.stderr+'\n')
def main():
    one('P-01','10.10.1.11');one('P-02','10.10.1.12',post=True)
    one('P-03','10.10.1.13',None);one('P-04','10.10.1.14','wrong-signature')
    one('P-05','10.10.1.15','insufficient-scope');one('P-06','10.10.1.16','valid','/api/%2e%2e/info')
    capture('P-07','10.10.1.17',p07)
    setup='\n'.join(curl('10.10.1.18','sg-ban-'+uuid.uuid4().hex[:12],'wrong-signature') for _ in range(4))
    textfile(out/'P-08_setup.txt','four bad signature curl requests to trigger ban',setup)
    capture('P-08','10.10.1.18',p08)
    capture('P-09','10.10.1.19',p09);capture('P-10','10.10.1.20',p10)
    routing()
    with (out/'MANIFEST.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(manifest[0]));w.writeheader();w.writerows(manifest)
    print('Manifest:',out/'MANIFEST.csv',flush=True)
if __name__=='__main__': main()
