import argparse,hashlib,json,subprocess,shutil
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/replay-protocol-images-v4';out.mkdir();tags=['twinet-msc:mldsa-construction-v2','tdn-hostap-pq:20261024-v3'];records=[];error=None
def run(cmd,timeout=60):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=timeout);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if r.returncode:raise RuntimeError(r.stderr)
 return r
try:
 for tag in tags:run(['docker','image','inspect',tag,'--format','{{json .}}'])
 archive=out/'images.tar.gz'
 with archive.open('wb')as stream:
  first=subprocess.Popen(['docker','save',*tags],stdout=subprocess.PIPE,stderr=subprocess.PIPE);last=subprocess.Popen(['gzip','-1'],stdin=first.stdout,stdout=stream,stderr=subprocess.PIPE);first.stdout.close();_,err=last.communicate(timeout=600);first.wait(timeout=30)
  records.append({'at':datetime.now(timezone.utc).isoformat(),'command':['docker save selected images','gzip -1'],'returncodes':[first.returncode,last.returncode],'stderr':first.stderr.read().decode()+err.decode()});assert first.returncode==last.returncode==0
 if shutil.which('go'):run(['go','version','-m',root/'scripts/twinet-linux'])
 else:records.append({'command':['go','version','-m'],'status':'Go tool unavailable on this worker; exact binary build information is captured separately with the local Go tool.'})
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':'Exact currently used generic runtime images, without container writable layers or credential/configuration bind mounts. Docker image inspection preserves actual content IDs and build metadata. Current source Dockerfiles and a dated ImageLock remain separate provenance and are not asserted to equal these builds.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'archive_bytes':(out/'images.tar.gz').stat().st_size if(out/'images.tar.gz').exists()else None}))
