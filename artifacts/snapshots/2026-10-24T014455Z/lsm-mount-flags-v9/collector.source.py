import hashlib,json,subprocess
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-continuation-2026-10-24T014455Z');out=root/'exports/lsm-mount-flags-v9';out.mkdir();name='tcv3-lsm-flags-v9';records=[];error=None
def run(argv,check=True):
 r=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=20);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,argv)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr)
 return r
try:
 run(['docker','run','-d','--name',name,'--network','none','--read-only','--tmpfs','/run','--tmpfs','/tmp','--entrypoint','sleep','twinet-msc:construction-v2','infinity'])
 run(['docker','inspect','--format','{{.Id}} {{.Image}} {{json .HostConfig.Tmpfs}} {{.HostConfig.ReadonlyRootfs}}',name])
 code="import json;from pathlib import Path;print(json.dumps([line for line in Path('/proc/self/mountinfo').read_text().splitlines()if line.split()[4]in ['/','/run','/tmp','/dev/shm']]))"
 run(['docker','exec',name,'python3','-c',code]);run(['uname','-a']);run(['cat','/proc/sys/kernel/random/boot_id'])
except Exception as exc:error=str(exc)
finally:
 run(['docker','rm','-f',name],False);(out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':'A fresh owned fixture without private credentials repeats only the read-only/tmpfs mount options used by the LSM experiment. Effective flags are supplementary observations; they are not represented as contemporaneous flags from the earlier removed containers. No protection bypass or data traffic is attempted.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'records':len(records)}))
