import argparse,difflib,hashlib,json,subprocess,tarfile
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--output',required=True);a=p.parse_args();root=Path(a.root);out=Path(a.output);out.mkdir();package='wpa_supplicant-2.12';archive=root/'scripts'/(package+'.tar.gz');final=root/'hostap-delay-fixed'/package;patch=[];sources=[];records=[];error=None
try:
 with tarfile.open(archive)as tar:
  for m in tar.getmembers():
   if not m.isfile()or not(m.name.endswith(('.c','.h'))or Path(m.name).name=='Makefile'):continue
   b=tar.extractfile(m).read();rel=Path(m.name).relative_to(package);target=final/rel
   if not target.exists():continue
   e=target.read_bytes()
   if b==e:continue
   patch.extend(difflib.unified_diff(b.decode().splitlines(True),e.decode().splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
   sources.append({'path':str(rel),'official_sha256':hashlib.sha256(b).hexdigest(),'final_sha256':hashlib.sha256(e).hexdigest()})
 (out/'final.patch').write_text(''.join(patch));(out/'wpa_supplicant.config').write_bytes((final/'wpa_supplicant/.config').read_bytes())
 expected=hashlib.sha256(archive.read_bytes()).hexdigest()
 (out/'reproduce.sh').write_text("""#!/bin/sh
set -eu
assets=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
target=$1
test -n "$target"
test ! -e "$target"
mkdir -p "$target"
cd "$target"
curl -fL -o wpa_supplicant-2.12.tar.gz https://w1.fi/releases/wpa_supplicant-2.12.tar.gz
echo '"""+expected+"""  wpa_supplicant-2.12.tar.gz' | sha256sum -c -
tar -xzf wpa_supplicant-2.12.tar.gz
cd wpa_supplicant-2.12
patch -p1 < "$assets/final.patch"
cp "$assets/wpa_supplicant.config" wpa_supplicant/.config
make -C wpa_supplicant -j4
wpa_supplicant/wpa_supplicant -v
sha256sum wpa_supplicant/wpa_supplicant
ldd wpa_supplicant/wpa_supplicant
""")
 work=root/'hostap-delay-reproduced';work.mkdir()
 with tarfile.open(archive)as tar:tar.extractall(work)
 tree=work/package
 for cmd in [['patch','-p1','-i',str(out/'final.patch')],['cp',str(out/'wpa_supplicant.config'),str(tree/'wpa_supplicant/.config')],['make','-C','wpa_supplicant','-j4'],['wpa_supplicant/wpa_supplicant','-v'],['sha256sum','wpa_supplicant/wpa_supplicant'],['ldd','wpa_supplicant/wpa_supplicant']]:
  r=subprocess.run(cmd,cwd=tree,capture_output=True,text=True,timeout=240);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':cmd,'cwd':str(tree),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  if r.returncode:raise RuntimeError(r.stderr[-1000:])
 for s in sources:assert hashlib.sha256((tree/s['path']).read_bytes()).hexdigest()==s['final_sha256']
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'official_archive':{'url':'https://w1.fi/releases/'+archive.name,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()},'changed_sources':sources,'records':records,'error':error,'prerequisites':['Linux compiler and make','OpenSSL development headers','libnl-3 and libnl-genl-3 development headers','curl, patch, tar and sha256sum'],'scope':'Complete difference from official release source plus active config. The clean source tree is rebuilt and all changed source hashes are checked against the executed final tree. Different build paths or toolchains can change binary hashes.'},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error,'sources':len(sources)}))
