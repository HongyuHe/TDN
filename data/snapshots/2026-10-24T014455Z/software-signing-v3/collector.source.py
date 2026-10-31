import argparse,hashlib,json,subprocess
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/software-signing-v3';out.mkdir();private=root/'private/software-signing-v3';private.mkdir(mode=0o700);records=[];error=None;image='twinet-msc:mldsa-construction-v2';binary=root/'scripts/twinet-linux'
def run(cmd,check=True,timeout=90):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=timeout)
 if 'PRIVATE KEY-----'in r.stdout:raise RuntimeError('Secret export refused')
 records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr[-1000:])
 return r
def container(cmd,extra=None):
 return ['docker','run','--rm','--network','none','-v',str(private)+':/private','-v',str(out)+':/public','-v',str(binary)+':/payload/twinet-linux:ro',*(extra or []),image,*cmd]
try:
 run(['docker','image','inspect',image,'--format','{{.Id}}'])
 manifest={'schema':'signed-software-test/v1','artifact':'twinet-linux','sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'bytes':binary.stat().st_size,'algorithm':'ML-DSA-87','publisher':'Synthetic laboratory publisher; no external approval','scope':'The executable artifact only; dynamic libraries, host kernel, verifier, public-key provisioning and firmware are outside this manifest.'}
 (out/'software-manifest.json').write_text(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n')
 for cmd in [['openssl','version','-a'],['openssl','genpkey','-algorithm','ML-DSA-87','-out','/private/publisher.key'],['openssl','pkey','-in','/private/publisher.key','-pubout','-out','/public/publisher.pub'],['openssl','pkeyutl','-sign','-rawin','-inkey','/private/publisher.key','-in','/public/software-manifest.json','-out','/public/software-manifest.sig']]:run(container(cmd))
 loader="""import hashlib,json,os,subprocess,sys
public='/public'
r=subprocess.run(['openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',public+'/publisher.pub','-in',public+'/software-manifest.json','-sigfile',public+'/software-manifest.sig'],capture_output=True,text=True)
if r.returncode:print(json.dumps({'signature_verified':False,'executed':False}));sys.exit(20)
m=json.load(open(public+'/software-manifest.json'));fd=os.open('/payload/twinet-linux',os.O_RDONLY);h=hashlib.sha256()
while True:
 data=os.read(fd,1048576)
 if not data:break
 h.update(data)
if h.hexdigest()!=m['sha256']or os.fstat(fd).st_size!=m['bytes']:print(json.dumps({'signature_verified':True,'payload_hash_verified':False,'executed':False}));sys.exit(21)
print(json.dumps({'signature_verified':True,'payload_hash_verified':True,'executing_verified_fd':True}),flush=True)
os.lseek(fd,0,os.SEEK_SET);os.execve(fd,['twinet-linux','--help'],os.environ)
"""
 (out/'verified_loader.py').write_text(loader)
 r=run(container(['python3','/public/verified_loader.py']),False);records[-1].update(probe='valid-signed-software-executes',expected_result='executed',observed_result='executed'if r.returncode==0 and '"executing_verified_fd": true'in r.stdout else'unexpected')
 altered=private/'twinet-altered';data=bytearray(binary.read_bytes());data[-1]^=1;altered.write_bytes(data);altered.chmod(0o755)
 args=container(['python3','/public/verified_loader.py']);index=args.index(str(binary)+':/payload/twinet-linux:ro');args[index]=str(altered)+':/payload/twinet-linux:ro';r=run(args,False);records[-1].update(probe='modified-software-not-executed',expected_result='hash-rejected',observed_result='hash-rejected'if r.returncode==21 and '"executed": false'in r.stdout else'unexpected')
 original=(out/'software-manifest.sig').read_bytes();bad=private/'bad.sig';changed=bytearray(original);changed[0]^=1;bad.write_bytes(changed)
 r=run(container(['python3','/public/verified_loader.py'],['-v',str(bad)+':/public/software-manifest.sig:ro']),False);records[-1].update(probe='modified-signature-not-executed',expected_result='signature-rejected',observed_result='signature-rejected'if r.returncode==20 else'unexpected')
 run(container(['openssl','pkey','-pubin','-in','/public/publisher.pub','-text_pub','-noout']))
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'runtime_backend':'Owned software release artifact signed and verified with actual OpenSSL ML-DSA-87','scope':['An actual Twinet executable is bound to a signed canonical manifest using Table 2 ML-DSA-87. The verifier checks the signature and exact executable bytes before executing the same opened file descriptor. Modified executable and signature controls must both reject execution.','Synthetic local publisher authority, trusted verifier and public-key provisioning remain explicit assumptions. Host root and Docker are trusted laboratory controls. This case does not sign every solution dependency, firmware image or boot chain, and does not establish product certification or organizational signing authority.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'probes':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
