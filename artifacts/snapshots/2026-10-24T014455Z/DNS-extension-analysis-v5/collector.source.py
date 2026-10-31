import hashlib,json,re
from datetime import datetime,timezone
from pathlib import Path
run=Path('artifacts/construction/2026-10-24T014455Z');base=Path('artifacts/snapshots/2026-10-24T014455Z');p=base/'native-DNS-hardening-v11';e=json.loads((p/'observations.json').read_text());assert not e['error'];probes=[r for r in e['records']if'probe'in r];assert len(probes)==20;assert all(r['expected_result']==r['observed_result']for r in probes)
summaries=[]
for node in ['ND_BLACK','ND_G_A1','ND_O_A1','ND_OF_A1','ND_G_B1','ND_O_B1','ND_OF_B1']:
    rules=[r for r in e['records']if r['command'][:3]==['docker','exec',node]and r['command'][3:]==['ip6tables-save','-c']]
    assert len(rules)==3
    def counts(text):
        return {proto:int(n)for n,proto in re.findall(r'\[(\d+):\d+\] -A OUTPUT -p (tcp|udp) -m (?:tcp|udp) --dport 53 -j REJECT',text)}
    before=counts(rules[-2]['stdout']);after=counts(rules[-1]['stdout']);assert set(after)=={'udp','tcp'};assert all(after[x]>before[x]for x in after)
    summaries.append({'device':node,'IPv6_counter_before':before,'IPv6_counter_after':after,'before_observation':rules[-2]['id'],'after_observation':rules[-1]['id']})
for i in [0,1]:
    records=[r for r in e['records']if r['command'][0]=='ssh'and str(22222+i)in r['command']]
    states=[r for r in records if r.get('state_table_empty')is not None];assert len(states)==1 and states[0]['state_table_empty']
    rules=[r for r in records if r['command'][-1]=='pfctl -sr -vv'];assert len(rules)==2
    def counters(text):
        found={}
        for header,count in re.findall(r'@\d+ ([^\n]+)\n  \[ Evaluations:.*?Packets: (\d+)',text):
            if 'inet6 proto'in header and'from ::1 to any port = domain'in header:found['tcp'if'proto tcp'in header else'udp']=int(count)
        return found
    b=counters(rules[0]['stdout']);a=counters(rules[1]['stdout']);assert set(a)=={'udp','tcp'}and all(a[x]>b[x]for x in a)
    summaries.append({'FreeBSD_port':22222+i,'PF_current_state_table_empty':True,'state_observation':states[0]['id'],'IPv6_loopback_rule_before':b,'IPv6_loopback_rule_after':a,'before_observation':rules[0]['id'],'after_observation':rules[1]['id']})
out=base/'DNS-extension-analysis-v5';out.mkdir();(out/'summary.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':summaries,'scope':'Counters are derived from exact retained effective policies. Empty current PF states are an independent checked condition. No IPv6 routed reachability beyond actual ::1 controls is asserted.'},indent=2)+'\n');(out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n')
paths=[base/'native-DNS-hardening-v8',base/'native-DNS-hardening-v9',base/'native-DNS-hardening-v10',p,out];checks=[]
for path in paths:
    m=json.loads((path/'manifest.json').read_text())
    for f in m['files']:assert hashlib.sha256((path/f['path']).read_bytes()).hexdigest()==f['sha256']
    checks.append({'path':str(path),'manifest_sha256':hashlib.sha256((path/'manifest.json').read_bytes()).hexdigest()})
r={'id':'C-DNS-002','request_id':'C-DNS-002','at':datetime.now(timezone.utc).isoformat(),'status':'finite-local-observations-delivered','groups':['RG-043'],'bundle_paths':[str(p)for p in paths],'checks':checks,'successful_checks':20,'scope':['All seven selected Linux devices now have leading IPv6 UDP53 and TCP53 OUTPUT REJECT rules. Exact previous rules, inserted rules, actual IPv6 addresses/routes and per-protocol counter increments are retained. Conventional IPv4 prefix rejection remains present.','Both actual FreeBSD Inners have enabled PF, complete current state tables that are empty, exact local IPv4/IPv6 addresses and expanded source-self DNS rules. IPv6 ::1 UDP/TCP probes increment the corresponding rules three packets each. Existing state bypass is not ignored; absence of current state is an explicit observed condition.','All 18 IPv6 conventional DNS probes reject and both nested protected-data directions deliver. The original v8 FreeBSD Python dependency failure is preserved; v9 through v11 use the existing drill utility with explicit IPv6/transport flags. Earlier Linux IPv6 loopback attempts encounter disabled IPv6 without rule hits. The final v11 enables only loopback through authorized host namespace control, assigns ::1/128 and verifies counter increments for both protocols. External interface IPv6 settings remain unchanged.','Resolver files, NSS configuration, actual libc identity and listening sockets/processes remain independent records. Musl routers identify musl1.2.5 through the loader diagnostic; nsswitch alone is not asserted to disable musl resolution. The Outers and FreeBSD retain their actual libc/linkage records. No DNS socket listener appears in the captured service inventory.','Direct IPv6 probes use actual loopback ::1; no externally routed IPv6 connectivity is invented. No requirement to prohibit encrypted DNS over arbitrary other ports is added. Complete default credentials, all future application behavior, remote bootstrap and organizational adoption remain separate.']}
target=run/'responses/C-DNS-002.json';target.write_text(json.dumps(r,indent=2)+'\n')
with(run/'requests_responses.jsonl').open('a')as f:f.write(json.dumps({'at':r['at'],'actor':'evidence','event':'response','path':str(target)})+'\n')
print(json.dumps({'response':str(target),'checks':20,'counter_bindings':len(summaries)}))
