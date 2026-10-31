import argparse,difflib,hashlib,json,shutil,subprocess,tarfile
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/hostap-pq-delay-build-v4';out.mkdir();target=root/'hostap-pq-delay';records=[];error=None
def run(cmd,cwd=None,check=True):
 r=subprocess.run(list(map(str,cmd)),cwd=cwd,capture_output=True,text=True,timeout=300);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'cwd':str(cwd)if cwd else None,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr[-2000:])
try:
 assert target.is_dir()
 patch=root/'exports/hostap-delay-reproduction-v5/final.patch'
 for product in ['hostapd','wpa_supplicant']:
  package=product+'-2.12';tree=target/package;work=tree/product
  saved=out/'before'/product;saved.mkdir(parents=True)
  for rel in ['src/pae/ieee802_1x_kay.c','src/pae/ieee802_1x_kay.h','src/drivers/driver_macsec_linux.c']:(saved/Path(rel).name).write_bytes((tree/rel).read_bytes())
  if 'evidence_delay_next'not in(tree/'src/pae/ieee802_1x_kay.h').read_text():run(['patch','-p1','-i',patch],tree)
  args=['docker','run','--rm','-v',str(root)+':'+str(root),'-w',str(work),'tdn-hostap-pq:20261024-v3']
  run(args+['make','clean']);run(args+['make','-j4'])
  for cmd in [['./'+product,'-v'],['ldd','./'+product],['openssl','version','-a'],['sha256sum','./'+product]]:run(args+cmd,check=cmd[-1]!='-v')
  (out/(product+'.config')).write_bytes((work/'.config').read_bytes())
  full=[];changed=[];archive=root/'scripts'/(package+'.tar.gz')
  with tarfile.open(archive)as tar:
   for m in tar.getmembers():
    if not m.isfile()or not(m.name.endswith(('.c','.h'))or Path(m.name).name=='Makefile'):continue
    old=tar.extractfile(m).read();relative=Path(m.name).relative_to(package);file=tree/relative
    if not file.is_file()or file.read_bytes()==old:continue
    new=file.read_bytes();full.extend(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),fromfile='a/'+str(relative),tofile='b/'+str(relative)));changed.append({'path':str(relative),'official_sha256':hashlib.sha256(old).hexdigest(),'final_sha256':hashlib.sha256(new).hexdigest()})
  (out/(product+'.full.patch')).write_text(''.join(full));(out/(product+'.source-hashes.json')).write_text(json.dumps({'official_url':'https://w1.fi/releases/'+archive.name,'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'changed':changed},indent=2)+'\n')
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['Separate owned objective EAP tree combines existing TLS 1.3 MLKEM1024/MLDSA87, 256-bit EAP-derived CAK KDF and L2 repair with final bounded-Hello/PN-history/Linux lowest-PN driver patches. Original v14 binaries remain unchanged.','Both hostapd and wpa_supplicant have complete final diffs from their exact official 2.12 source archives, active build config, source hashes, binary hashes and runtime library identities. Finite EAP delayed-data behavior remains a separate execution test.','IEEE normative KDF/agility review and complete standard conformance remain separate from matching locally patched implementations.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':str(p.relative_to(out)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.rglob('*')if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error}))
 if error:raise SystemExit(1)
