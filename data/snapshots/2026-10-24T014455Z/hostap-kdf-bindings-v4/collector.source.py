import argparse,hashlib,json,subprocess
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/hostap-kdf-bindings-v4';out.mkdir();records=[];error=None
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
try:
 official=root/'exports/hostap-kdf-vectors-v3/build/src'
 for product,wrapper,binary in [('hostapd-2.12','src/ap/wpa_auth_kay.c','hostapd/hostapd'),('wpa_supplicant-2.12','wpa_supplicant/wpas_kay.c','wpa_supplicant/wpa_supplicant')]:
  tree=root/'hostap-pq-delay-auth'/product
  for rel in ['src/pae/ieee802_1x_key.c','src/crypto/crypto_openssl.c','src/pae/ieee802_1x_kay.c',wrapper]:
   source=tree/rel;target=out/product/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read_bytes());record={'at':datetime.now(timezone.utc).isoformat(),'path':str(source),'sha256':sha(source),'copied_public_source':str(target.relative_to(out))}
   if rel in ['src/pae/ieee802_1x_key.c','src/crypto/crypto_openssl.c']:record['matches_tested_official_source']=sha(source)==sha(official/rel.removeprefix('src/'));assert record['matches_tested_official_source']
   records.append(record)
  exe=tree/binary;argv=['docker','run','--rm','--network','none','-v',str(exe)+':/runtime/program:ro','tdn-hostap-pq:20261024-v3','sh','-c','sha256sum /runtime/program; ldd /runtime/program; openssl version']
  r=subprocess.run(argv,text=True,capture_output=True,timeout=30);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':argv,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0
except Exception as exc:error=str(exc)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':'Read-only public final authenticator and supplicant source/binary bindings. Both exact derivation and OpenSSL CMAC source files must match the official bytes used by the separate12-vector harness. No live credential material is read.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':str(f.relative_to(out)),'sha256':sha(f)}for f in out.rglob('*')if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'records':len(records)}))
