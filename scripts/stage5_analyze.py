"""Build derived verification and annotation guide from Stage 5 capture exports."""
import csv, io, json, os, re, sys, shutil
from datetime import datetime, timezone
from pathlib import Path
root=Path('/work'); out=root/sys.argv[1]
def rows(case,point):
    s=(out/case/(point+'_summary.csv')).read_text()
    return list(csv.DictReader(io.StringIO(s[s.index('frame.number,'):]),escapechar=None))
def reqs(rs): return [r for r in rs if r['http.request.method']]
def ids(rs):
    return set(re.findall(r'X-Request-ID: ([A-Za-z0-9-]+)', ' '.join(r['http.request.line'] for r in rs), re.I))
def readmanifest(): return list(csv.DictReader((out/'MANIFEST.csv').open(newline='')))
manifest=readmanifest()
runlog=(out/'run.txt').read_text(encoding='utf-8')
match=re.search(r'^Overrides: (.+)$',runlog,re.M)
if not match: raise RuntimeError('configuration overrides missing from run log')
overrides=match.group(1)
for m in manifest:
    m['configuration_overrides']=overrides
    p=out/m['scenario']/(m['point']+'_capinfos.txt'); s=p.read_text()
    def field(k):
        match=re.search(r'^'+re.escape(k)+r':\s*(.*)$',s,re.M)
        return match.group(1).strip() if match else 'no packets'
    if 'capture_ended_utc' in m: m['verification_timestamp_utc']=m.pop('capture_ended_utc')
    m['first_packet_utc']=field('First packet time')
    m['last_packet_utc']=field('Last packet time')
with (out/'MANIFEST.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=manifest[0].keys());w.writeheader();w.writerows(manifest)
mindex={(m['scenario'],m['point']):m for m in manifest}
data={(f'P-{i:02}',p):rows(f'P-{i:02}',p) for i in range(1,11) for p in ['P1','P2','P3','P4']}
checks=[]
def add(name,ok,detail): checks.append({'check':name,'result':'PASS' if ok else 'FAIL','details':detail})
badlength=[f'{c}/{p}/{r["frame.number"]}' for (c,p),rs in data.items() for r in rs if r['frame.len']!=r['frame.cap_len']]
badcap=[m['scenario']+'/'+m['point'] for m in manifest if not re.search(r'/0 \(pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0\)',m['drop_report'])]
add('full frame lengths',not badlength,'truncated: '+str(badlength))
add('kernel and capture drops',not badcap,'nonzero or unavailable: '+str(badcap))
for i in range(1,11):
 c=f'P-{i:02}';counts=[int(mindex[c,p]['packet_count']) for p in ('P1','P2','P3','P4')]
 add(c+' P1-P3 packets',all(counts[:3]) if i!=9 else counts[0]>0,'P1/P2/P3/P4='+str(counts))
if not reqs(data['P-01','P1']): raise RuntimeError('P-01 HTTP decoding missing')
r1=reqs(data['P-01','P1'])[0];r4=reqs(data['P-01','P4'])[0]
ladder=[]
for p in ('P1','P2','P3','P4'):
 r=reqs(data['P-01',p])[0];ladder.append(r['ip.ttl'])
add('P-01 TTL ladder',ladder==['64','63','62','64'],'P1/P2/P3/P4: '+str(ladder))
common=ids([r1]) & ids([r4])
add('P-01 request ID',bool(common),'common '+str(sorted(common)))
add('proxy boundary',r1['ip.src']!=r4['ip.src'] and r1['tcp.dstport']=='8000' and r4['tcp.dstport']=='9000',f"P1 {r1['ip.src']}:{r1['tcp.srcport']} -> {r1['ip.dst']}:{r1['tcp.dstport']} stream {r1['tcp.stream']}; P4 {r4['ip.src']}:{r4['tcp.srcport']} -> {r4['ip.dst']}:{r4['tcp.dstport']} stream {r4['tcp.stream']}; stream IDs are local")
header=r4['http.request.line']
add('forwarded identity', 'X-Forwarded-For: 10.10.1.11' in header,'P4 request '+r4['frame.number'])
add('backend Authorization', 'authorization:' not in header.lower(),'P4 request '+r4['frame.number'])
for n in range(3,9):
 c=f'P-{n:02}'; p1=data[c,'P1']; p4=data[c,'P4']
 if n==7:
  client=(out/c/'client.txt').read_text(); patterns=re.findall(r'X-Request-ID: (sg-p07-[a-z0-9]+)',client); rejected={patterns[-1]} if patterns else set()
 else: rejected=ids(p1)
 crossed=rejected & ids(p4)
 add(c+' rejected ID absent at P4',bool(rejected) and not crossed,'request IDs '+str(sorted(rejected))+'; P4 captured packets '+str(len(p4))+'; HTTP ID match '+str(sorted(crossed)))
clientip=[f'{c}/{p}/{r["frame.number"]}' for (c,p),rs in data.items() if p=='P4' for r in rs if re.search(r'10\.10\.1\.\d+',r['ip.src']+','+r['ip.dst'])]
add('no client IP at P4',not clientip,str(clientip))
icmp=[r for r in data['P-09','P1'] if r['icmp.type'].split(',')[0]=='3']
add('P-09 ICMP unreachable',bool(icmp) and icmp[0]['ip.src'].split(',')[0]=='10.10.1.1' and icmp[0]['icmp.code'].split(',')[0]=='0',str([(x['frame.number'],x['ip.src'],x['icmp.type'],x['icmp.code']) for x in icmp]))
up=reqs(data['P-10','P4']);add('P-10 upstream reuse',len(up)==2 and up[0]['tcp.stream']==up[1]['tcp.stream'],'upstream request frames/streams '+str([(x['frame.number'],x['tcp.stream'],x['tcp.srcport']) for x in up]))
with (out/'verification.csv').open('w',newline='') as f:
 f.write('UTC: '+datetime.now(timezone.utc).isoformat()+'\nCOMMAND: python scripts/stage5_analyze.py '+str(out.relative_to(root))+'\nDERIVED FROM CAPTURE SUMMARIES\n')
 w=csv.DictWriter(f,fieldnames=['check','result','details']);w.writeheader();w.writerows(checks)
profile=out/'wireshark_profile';profile.mkdir(exist_ok=True)
(profile/'decode_as_entries').write_text('decode_as_entry: tcp.port,8000,(none),http\ndecode_as_entry: tcp.port,9000,(none),http\n')
(profile/'preferences').write_text('gui.column.format: "No.", "%m", "Source", "%Cus:ip.src:0:R", "Destination", "%Cus:ip.dst:0:R", "TTL", "%Cus:ip.ttl:0:R", "Src port", "%Cus:tcp.srcport:0:R", "Dst port", "%Cus:tcp.dstport:0:R", "Stream", "%Cus:tcp.stream:0:R", "Flags", "%Cus:tcp.flags.str:0:R", "Seq", "%Cus:tcp.seq:0:R", "Ack", "%Cus:tcp.ack:0:R", "Method", "%Cus:http.request.method:0:R", "URI", "%Cus:http.request.uri:0:R", "Status", "%Cus:http.response.code:0:R", "Info", "%i"\n')
guide=['# Stage 5 packet evidence','',f'Run: `{out.relative_to(root)}`. Generated from the real tshark field exports; pcapng files are private and contain disposable bearer tokens. Times are UTC. TCP stream numbers are local to each capture.','',
'Install the wireshark_profile directory as a Wireshark profile via Edit > Configuration Profiles > Import, or copy it into the personal Wireshark profiles directory and select it. If decode-as entries do not load, use Analyze > Decode As and set TCP ports 8000 and 9000 to HTTP.','',
'In screenshots hide or mask Authorization values; leave raw pcapng files unchanged. For each selected packet annotate source/destination IP and ports, TTL, TCP flags, relative seq/ack, method/URI or status, request ID and X-Forwarded-For where present.','',
'See verification.csv for capture-derived findings. Stream numbers are local to each file.','']
for i in range(1,11):
 c=f'P-{i:02}';guide += [f'## {c}','',f'Client output: `{out.relative_to(root) / c / "client.txt"}`.','']
 for p in ('P1','P2','P3','P4'):
  rs=data[c,p]; requests=[r['frame.number'] for r in rs if r['http.request.method']]; responses=[r['frame.number'] for r in rs if r['http.response.code']]; syn=[r['frame.number'] for r in rs if 'S' in r['tcp.flags.str']]; fins=[r['frame.number'] for r in rs if 'F' in r['tcp.flags.str']]
  filt='icmp || tcp.port == 9000' if i==9 else ('tcp.port == 9000' if p=='P4' else 'tcp.port == 8000')
  guide.append(f'- {p}: `{out.relative_to(root) / c / (p+".pcapng")}`; {len(rs)} packets. Filter: `{filt}`. Request frames {requests}, response frames {responses}, SYN frames {syn}, FIN frames {fins}. Screenshot suggestion: `evidence/screenshots/{c}-{p}-exchange.png`. '+('No packets were captured at this point.' if not rs else 'Inspect the listed frames and packet details; see the matching summary CSV.'))
 guide.append('')
guide += ['## Findings and limits', '', 'The following results are derived from this run’s capture summaries:', '']
for check in checks:
 guide.append(f"- {check['check']}: {check['result']} — {check['details']}")
guide += ['', 'P-01: use the listed SYN, request, response and FIN frames and the matching summary for sequence and acknowledgement numbers. HTTP fields may require TCP reassembly.']
(root/'docs/packet_evidence.md').write_text('\n'.join(guide)+'\n',encoding='utf-8')
shutil.copyfile(out/'MANIFEST.csv',out.parent/'MANIFEST.csv')
shutil.copytree(profile,out.parent/'wireshark_profile',dirs_exist_ok=True)
print(json.dumps(checks,indent=2))
if any(x['result']!='PASS' for x in checks): raise SystemExit(1)
