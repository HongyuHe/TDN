import argparse,hashlib,json,subprocess
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/audit-protected-offload-v6';out.mkdir();records=[];error=None;key=Path('/users/hy/tdn-replay-20261024-v6/private/freebsd/management_key')
def guest(cmd,expect=None,label=None):
 begin=datetime.now(timezone.utc).isoformat();argv=['ssh','-o','BatchMode=yes','-i',str(key),'-p','22352','root@127.0.0.1',cmd];r=subprocess.run(argv,capture_output=True,text=True,timeout=20);assert '-----BEGIN PRIVATE KEY-----'not in r.stdout;record={'id':'offload6-%04d'%len(records),'started_at':begin,'ended_at':datetime.now(timezone.utc).isoformat(),'command':argv,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
 if expect:record.update(probe=label,expected_result=expect,observed_result=expect if(r.returncode==0)==(expect=='accepted')else'contrary-result')
 records.append(record);return r
try:
 common='/var/db/tdn-audit-exporter/audit-export-client --url https://198.22.255.18:43463/v1/audit --log /var/db/tdn-audit-exporter/actual-audit-source.log --ca /var/db/tdn-audit-exporter/tls/ca.pem --cert /var/db/tdn-audit-exporter/tls/client.pem --key /var/db/tdn-audit-exporter/tls/client.key '
 guest('cat /var/db/tdn-audit-exporter/cursor.json; sha256 /var/db/tdn-audit-exporter/actual-audit-source.log; stat -f "%Sp %Su %Sg %N" /var/db/tdn-audit-exporter/tls/client.key')
 guest(common+'--cursor /var/db/tdn-audit-exporter/restart-cursor-v6.json','accepted','duplicate-after-collector-restart')
 guest(common.replace(':43463/',':43464/')+'--cursor /var/db/tdn-audit-exporter/budget-cursor-v6.json','rejected','configured-store-budget-backpressure')
 guest('test ! -e /var/db/tdn-audit-exporter/budget-cursor-v6.json','accepted','no-source-cursor-after-denied-store')
 guest('printf %s synthetic-conflicting-record > /var/db/tdn-audit-exporter/conflict-v6.log')
 guest(common.replace('actual-audit-source.log','conflict-v6.log')+'--cursor /var/db/tdn-audit-exporter/conflict-cursor-v6.json','rejected','conflicting-record-at-committed-offset')
 guest('test ! -e /var/db/tdn-audit-exporter/conflict-cursor-v6.json','accepted','no-source-cursor-after-conflict')
 guest("su -m nobody -c 'test -r /var/db/tdn-audit-exporter/tls/client.key'",'rejected','unprivileged-guest-principal-cannot-read-export-key')
 guest('cat /var/db/tdn-audit-exporter/cursor.json; sha256 /var/db/tdn-audit-exporter/actual-audit-source.log')
except Exception as exc:error=str(exc)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['The restarted actual collector must reconstruct the committed audit transaction and accept an identical retry. A separate configured128-byte store returns507 and source cursor creation must not occur. A different record at the committed offset returns409.','The nobody principal tests one actual FreeBSD file/directory permission boundary. Guest root, source agent, provisioning and hypervisor remain trusted controls. The negative check does not establish every administrator or debugging interface inaccessible.','Configured application capacity is explicit; physical disk exhaustion, annual retention and source log rotation remain separate.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'probes':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
