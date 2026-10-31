import hashlib,json,shlex,socket,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-replay-20261024-v7');out=root/'exports/freebsd-certificate-events-v4';out.mkdir();private=root/'private/freebsd-native-creds';work=root/'private/freebsd-certificate-events-v4';work.mkdir(mode=0o700);records=[];started=datetime.now(timezone.utc).isoformat();error=None
spec=json.loads((root/'scripts/profiles/native-replay-v7.json').read_text())
def run(argv,check=True,timeout=45):
 t=datetime.now(timezone.utc).isoformat();r=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=timeout)
 if '-----BEGIN PRIVATE KEY-----' in r.stdout or '-----BEGIN EC PRIVATE KEY-----' in r.stdout:raise RuntimeError('Secret export refused')
 records.append({'id':'diversity-%04d'%len(records),'command':list(map(str,argv)),'started_at':t,'ended_at':datetime.now(timezone.utc).isoformat(),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(json.dumps(records[-1]))
 return r
def ex(did,*cmd,check=True):return run(['docker','exec',did,*cmd],check)
def ssh(i,cmd,check=True,timeout=45):return run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-i',root/'private/freebsd/management_key','-p',22392+i,'root@127.0.0.1',cmd],check,timeout)
def hmp(i,command):
 path=root/'private/freebsd'/('monitor-v2-'+str(i)+'.sock');s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(2);s.connect(str(path));greeting=s.recv(4096).decode(errors='replace');s.sendall((command+'\n').encode());time.sleep(.2)
 try:result=s.recv(16384).decode(errors='replace')
 except socket.timeout:result=''
 s.close();records.append({'id':'hmp-%04d'%len(records),'command':['qemu-monitor',str(path),command],'returncode':0,'stdout':greeting+result,'stderr':''})
 if 'Error:' in result:raise RuntimeError(result)
def copy_guest(i,source,dest):
 return run(['scp','-q','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-i',root/'private/freebsd/management_key','-P',22392+i,source,'root@127.0.0.1:'+dest])
def reload(i):
 ssh(i,'/usr/local/sbin/swanctl --flush-certs',check=False)
 ssh(i,'/usr/local/sbin/swanctl --load-creds --clear')
 ssh(i,'/usr/local/sbin/swanctl --load-conns')
def stop():
 for i in [0,1]:
  ssh(i,'/usr/local/sbin/swanctl --uninstall --child protected',check=False)
  ssh(i,'/usr/local/sbin/swanctl --terminate --ike msc',check=False)
try:
 ca=root/'private/native-replay-v7/ca/inner-s1'
 (work/'index').write_text('');(work/'serial').write_text('9000\n');(work/'crlnumber').write_text('9000\n')
 (work/'newcerts').mkdir()
 cfg='[ca]\ndefault_ca=c\n[c]\ndatabase='+str(work/'index')+'\nnew_certs_dir='+str(work/'newcerts')+'\ncertificate='+str(ca/'ca.pem')+'\nprivate_key='+str(ca/'ca-key.pem')+'\nserial='+str(work/'serial')+'\ncrlnumber='+str(work/'crlnumber')+'\ndefault_md=sha384\ndefault_days=1\ndefault_crl_days=1\ncrl_extensions=crl_ext\npolicy=p\nx509_extensions=e\n[p]\ncommonName=supplied\n[e]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:NQ_I_B1.msc.test\nextendedKeyUsage=1.3.6.1.5.5.8.2.2\n[crl_ext]\nauthorityKeyIdentifier=keyid:always\n'
 (work/'openssl.cnf').write_text(cfg)
 bcert=private/'B/swanctl/x509/cert.pem'
 run(['openssl','ca','-batch','-config',work/'openssl.cnf','-revoke',bcert,'-crl_reason','certificateHold'])
 run(['openssl','ca','-batch','-config',work/'openssl.cnf','-gencrl','-out',work/'hold.crl.pem'])
 run(['openssl','crl','-in',work/'hold.crl.pem','-noout','-text','-verify','-CAfile',ca/'ca.pem'])
 (out/'hold.crl.pem').write_bytes((work/'hold.crl.pem').read_bytes())
 stop();copy_guest(0,work/'hold.crl.pem','/usr/local/etc/swanctl/x509crl/ca.crl.pem');reload(0)
 r=ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',check=False,timeout=90);records[-1].update(probe='actual-gateway-revoked-peer',expected_result='rejected',observed_result='rejected' if r.returncode else 'accepted')
 r=ex('NQ_R_A1','ping','-n','-c','3','-W','1','10.2.1.10',check=False);records[-1].update(probe='revoked-peer-payload',expected_result='no_reply',observed_result='delivered' if r.returncode==0 else 'no_reply')
 for i in [0,1]:ssh(i,'cat /root/tdn-freebsd-v3/charon-runtime.log')
 copy_guest(0,private/'A/swanctl/x509crl/ca.crl.pem','/usr/local/etc/swanctl/x509crl/ca.crl.pem');reload(0)
 run(['openssl','req','-new','-sha384','-key',private/'B/swanctl/private/key.pem','-out',work/'expired.csr','-subj','/CN=NQ_I_B1.msc.test'])
 run(['openssl','ca','-batch','-config',work/'openssl.cnf','-in',work/'expired.csr','-out',work/'expired.pem','-startdate','251001000000Z','-enddate','251002000000Z'])
 run(['openssl','x509','-in',work/'expired.pem','-noout','-text'])
 (out/'expired.public.pem').write_bytes((work/'expired.pem').read_bytes())
 stop();copy_guest(1,work/'expired.pem','/usr/local/etc/swanctl/x509/cert.pem');reload(1);reload(0)
 r=ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',check=False,timeout=90);records[-1].update(probe='actual-gateway-expired-peer',expected_result='rejected',observed_result='rejected' if r.returncode else 'accepted')
 r=ex('NQ_R_A1','ping','-n','-c','3','-W','1','10.2.1.10',check=False);records[-1].update(probe='expired-peer-payload',expected_result='no_reply',observed_result='delivered' if r.returncode==0 else 'no_reply')
 for i in [0,1]:ssh(i,'cat /root/tdn-freebsd-v3/charon-runtime.log')
except Exception as e:error=str(e)
finally:
 try:
  copy_guest(0,private/'A/swanctl/x509crl/ca.crl.pem','/usr/local/etc/swanctl/x509crl/ca.crl.pem')
  copy_guest(1,private/'B/swanctl/x509/cert.pem','/usr/local/etc/swanctl/x509/cert.pem')
  for i in [0,1]:reload(i);ssh(i,'/usr/local/sbin/swanctl --load-all')
  ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',check=False,timeout=90)
  r=ex('NQ_R_A1','ping','-n','-c','3','-W','1','10.2.1.10',check=False);records[-1].update(probe='valid-peer-restored',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply')
 except Exception as e:
  if error is None:error=str(e)
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['Actual FreeBSD/Botan IKE gateways use a signed certificate-hold CRL and a separately signed expired certificate under the owned ND test CA. Original working certificate and CRL are restored at completion.','The temporary CRL database is separate from the original profile CA files. These are private laboratory test credentials, not operational issuance/revocation or organizational authority.','Rejection must be matched to actual certificate diagnostic, not inferred from a timeout or nonzero command alone. Public observations retain both daemon diagnostic and finite payload controls.']},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error,'probes':[{k:r[k] for k in ['probe','expected_result','observed_result']} for r in records if 'probe'in r]}))
