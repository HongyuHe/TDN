import argparse,hashlib,json,subprocess,tarfile
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/hostap-kdf-vectors-v3';out.mkdir();build=out/'build';build.mkdir();records=[];error=None
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def command(argv,check=True):
 r=subprocess.run(argv,text=True,capture_output=True,timeout=120);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':argv,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr[-2000:])
 return r
try:
 archive=root/'public-sources/wpa_supplicant-2.12.tar.gz';assert sha(archive)=='08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6'
 with tarfile.open(archive)as t:
  for member in t.getmembers():
   rel=Path(member.name).relative_to('wpa_supplicant-2.12')
   if member.isfile()and ((str(rel).startswith('src/')and rel.suffix=='.h')or str(rel)in ['src/pae/ieee802_1x_key.c','src/crypto/crypto_openssl.c']):
    target=build/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(t.extractfile(member).read())
 official=build/'src/pae/ieee802_1x_key.c';crypto=build/'src/crypto/crypto_openssl.c';text=crypto.read_text();begin=text.index('int omac1_aes_vector(');end=text.index('struct crypto_bignum * crypto_bignum_init(',begin)
 cmac='#include "utils/includes.h"\n#include "utils/common.h"\n#include <openssl/evp.h>\n#include <openssl/params.h>\n#include <openssl/err.h>\n#define TEST_FAIL() 0\n'+text[begin:end];(build/'cmac-source-subset.c').write_text(cmac)
 runtime=root/'hostap-pq-delay-auth/wpa_supplicant-2.12/src'
 assert sha(runtime/'pae/ieee802_1x_key.c')==sha(official);assert sha(runtime/'crypto/crypto_openssl.c')==sha(crypto)
 for name in ['pae/ieee802_1x_key.c','crypto/crypto_openssl.c','pae/ieee802_1x_kay.c']:
  target=out/('runtime-'+Path(name).name);target.write_bytes((runtime/name).read_bytes())
 wrapper=root/'hostap-pq-delay-auth/wpa_supplicant-2.12/wpa_supplicant/wpas_kay.c';(out/'runtime-wpas_kay.c').write_bytes(wrapper.read_bytes())
 (build/'vector-harness.c').write_text((Path(__file__).with_name('hostap_kdf_harness_v3.c')).read_text())
 image='tdn-hostap-pq:20261024-v3';identity=command(['docker','image','inspect',image,'--format','{{.Id}}']).stdout.strip();assert identity=='sha256:b6bb2db742723c974b511b82c98a4c17238efd6cf5a5b84be37b7f44392a19d5'
 docker=['docker','run','--rm','--network','none','-v',str(out)+':/work','-w','/work/build',image]
 command(docker+['sh','-c','cc -O2 -I src -I src/utils vector-harness.c cmac-source-subset.c -lcrypto -lssl -o kdf-vectors && ./kdf-vectors VERSION && ldd kdf-vectors'])
 key128='e68a1ab90313024fda7a04a03fea010f';key256='3946ec36f59017f1267e914abed2dbf6633f52ae7e20309d3eefdda4073adfad';macs='001b6393fcbc00d0b71a7717';sid='0dd075693f54b2b2eb01da61f0af5d429b65b1ebcaf536fba350777598571728f630c5c8da5475489ad47b6e3489a97372e5a8fd550617972c020d42a3b13a4eae';cak128='135bd758b0ee5c11c55ff6ab19fdb199';cak256='a29efdb63d6fba73c65daab2295340a837a8886e94a905b5c9c7ef1d9dbb297e';ckn128='96437a93ccf10d9dfe347846cce52c7d';ckn256='7888f5d48ba8b24e96bb95bd8c7304ec'
 vectors=[['G1-128','KDF','1ab9024fa04a03feb9024fa04a03fe11','01020104',16,'b57a0b05f43e9600c3c4d15c1e3c26e8'],['G1-256','KDF',key256,'01020104',32,'0efd01e5b03a0951a6df9bbffe419016ee40fdbfc3335ebf92ea03802214a307'],['G2-128','CAK',key128,macs,16,cak128],['G2-256','CAK',key256,macs,32,cak256],['G3-128','CKN',key128,sid+macs,16,ckn128],['G3-256','CKN',key256,sid+macs,16,ckn256],['G4-128','KEK',cak128,ckn128,16,'8f5a384c15d6ae9302b462e363d03ca6'],['G4-256','KEK',cak256,ckn256,32,'71340e454c84a1232aa7977d5ed86f78f250f3f9d53584b9337ff0c6dfdc9f96'],['G5-128','ICK',cak128,ckn128,16,'8f1c5cb1c8ed2e5f047906e0473aad4d'],['G5-256','ICK',cak256,ckn256,32,'98b8544d7390a41e50ef72e25b4a036523c919e812918871949b48123eab526e'],['G6-128','SAK',cak128,'0102030405060708090a0b0c0d0e0f10cd421cf86ba457938657675b01020304050607080d1f36cf00000001',16,'045205925831ae59c14550ed59cc003d'],['G6-256','SAK',cak256,'0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00cd421cf86ba457938657675b01020304050607080d1f36cf00000001',32,'bb692568b287484a5f3f4793b09732270d13dd818373c15b3f2793fdc1948a37']]
 for label,mode,key,context,n,expected in vectors:
  r=command(docker+['./kdf-vectors',mode,key,context,str(n)]);observed=r.stdout.strip();records[-1].update(probe=label,expected_result=expected,observed_result=observed);assert observed==expected,label
 (out/'vectors.json').write_text(json.dumps(vectors,indent=2)+'\n')
except Exception as exc:error=str(exc)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'hostap_kdf_harness_v3.c').write_bytes(Path(__file__).with_name('hostap_kdf_harness_v3.c').read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['Published IEEE Annex G example inputs are public noncredential vectors. No live MSK, CAK, KEK, ICK or SAK bytes are read or exported.','The unchanged official ieee802_1x_key.c is included directly in a test translation unit. Original OpenSSL CMAC function bytes are extracted without editing, with normal build includes and TEST_FAIL disabled. The helper confirms both full runtime source files match official archive bytes. The harness tests actual derivation functions with OpenSSL3.5.5 in the pinned authorized runtime image; it does not invoke the already linked hostapd ELF functions directly.','IEEE primary-publication indexed text has the preserved hosting/authenticity caveat. G3 uses the complete p285 Session-ID because its p286 indexed repeat has an odd-length malformed hexadecimal group. Matching vectors establish these finite derivations, not full standard conformance or independent interoperability.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':str(f.relative_to(out)),'sha256':sha(f)}for f in out.rglob('*')if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'records':len(records)}))
