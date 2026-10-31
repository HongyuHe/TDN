import argparse,hashlib,json,subprocess
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--device-prefix',default='ND');p.add_argument('--guest-port-base',type=int,default=22222);a=p.parse_args();root=Path(a.root);out=root/'exports/freebsd-PF-skip-v13';out.mkdir();records=[];error=None
def run(cmd,check=True):
    begin=datetime.now(timezone.utc).isoformat();r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=40);assert '-----BEGIN PRIVATE KEY-----'not in r.stdout;records.append({'id':'pf13-%04d'%len(records),'started_at':begin,'ended_at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
    if check and r.returncode:raise RuntimeError(json.dumps(records[-1]))
    return r
def ssh(i,cmd,check=True):return run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-i',root/'private/freebsd/management_key','-p',str(a.guest_port_base+i),'root@127.0.0.1',cmd],check)
try:
    for i in [0,1]:
        for cmd in ['freebsd-version -kru','uname -a','sysctl kern.hostuuid kern.boottime','ifconfig -a','pfctl -vvs Interfaces','cat /etc/pf.conf','sha256 /etc/pf.conf','pfctl -si','pfctl -ss -vv','pfctl -sa -vv','pfctl -sr -vv','pfctl -sn -vv','pfctl -s Anchors -v',"pfctl -a '*' -sr -vv","pfctl -a '*' -sn -vv",'pfctl -s Tables -v','pfctl -s memory','pfctl -s timeouts']:
            ssh(i,cmd,check=False)
    for src,dst in [(a.device_prefix+'_R_A1','10.2.1.10'),(a.device_prefix+'_R_B1','10.1.1.10')]:
        r=run(['docker','exec',src,'ping','-n','-c','3','-W','1',dst],False);records[-1].update({'probe':'useful-protected-'+src,'expected_result':'delivered','observed_result':'delivered'if r.returncode==0 else'no-reply'})
    for i in [0,1]:
        ssh(i,'ifconfig -a');ssh(i,'pfctl -vvs Interfaces');ssh(i,'pfctl -si');ssh(i,'pfctl -ss -vv');ssh(i,'pfctl -sr -vv');ssh(i,'pfctl -sn -vv')
except Exception as e:error=str(e)
finally:
    (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['Read-only effective PF collection on the two original ND actual FreeBSD Inners. Effective per-interface skip flags and complete all-settings output, filter rules, translation, recursive anchor rules, tables, normalization-visible configuration, enabled state and current states are separate observations. No rules or states are changed.','Actual local interfaces bind expanded self-source rules. Before/after current states and PF status accompany useful protected traffic in both directions. Collection is an interval, not an atomic or all-future-state claim.','The official FreeBSD releng/14.4 source review is separate from actual OS/kernel and CLI observations. Imported predicates must check absence of translation/normalization/state-creating rules rather than infer it solely from a DNS deny list. Host and guest root remain trusted administrative controls.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'records':len(records)}))
