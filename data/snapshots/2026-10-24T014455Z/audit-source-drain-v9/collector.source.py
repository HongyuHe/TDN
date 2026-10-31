import argparse,hashlib,json,subprocess
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/audit-source-drain-v9';out.mkdir();records=[];error=None
def guest(cmd):
 argv=['ssh','-o','BatchMode=yes','-i','/users/hy/tdn-replay-20261024-v6/private/freebsd/management_key','-p','22352','root@127.0.0.1',cmd];r=subprocess.run(argv,text=True,capture_output=True,timeout=20);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':argv,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr});return r
try:
 r=guest('stat -f %z /var/db/tdn-audit-exporter/actual-audit-source.log; cat /var/db/tdn-audit-exporter/cursor.json');assert r.returncode==0
 size=int(r.stdout.splitlines()[0]);assert size<4000000
 common='/var/db/tdn-audit-exporter/audit-export-client --url https://198.22.255.18:43463/v1/audit --log /var/db/tdn-audit-exporter/actual-audit-source.log --ca /var/db/tdn-audit-exporter/tls/ca.pem --cert /var/db/tdn-audit-exporter/tls/client.pem --key /var/db/tdn-audit-exporter/tls/client.key --cursor /var/db/tdn-audit-exporter/cursor.json'
 for attempt in range(64):
  r=guest(common);assert r.returncode==0
  if 'no new audit bytes'in r.stdout:break
 else:raise RuntimeError('Bounded drain did not reach EOF')
 r=guest('cat /var/db/tdn-audit-exporter/cursor.json; printf '\\n'; stat -f %z /var/db/tdn-audit-exporter/actual-audit-source.log; sha256 /var/db/tdn-audit-exporter/actual-audit-source.log');lines=r.stdout.splitlines();cursor=json.loads(lines[0]);assert cursor['offset']==int(lines[1])==size
 records.append({'at':datetime.now(timezone.utc).isoformat(),'probe':'complete-recorded-audit-source-acknowledged','expected_result':'accepted','observed_result':'accepted','bytes':size})
except Exception as exc:error=str(exc)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':'Drain the exact stable source copy retained by v5, including its final actual audit marker. Only size, hashes, cursor and protocol acknowledgement metadata are exported.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'records':len(records)}))
