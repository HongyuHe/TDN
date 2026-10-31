import hashlib,json,shlex,socket,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-replay-20261024-v6');out=root/'exports/freebsd-native-integration-v8';out.mkdir();private=root/'private/freebsd-native-creds';private.mkdir(mode=0o700,exist_ok=True);records=[];started=datetime.now(timezone.utc).isoformat();error=None
spec=json.loads((root/'scripts/profiles/native-replay-v6.json').read_text())
def run(argv,check=True,timeout=45):
 t=datetime.now(timezone.utc).isoformat();r=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=timeout)
 if '-----BEGIN PRIVATE KEY-----' in r.stdout or '-----BEGIN EC PRIVATE KEY-----' in r.stdout:raise RuntimeError('Secret export refused')
 records.append({'id':'diversity-%04d'%len(records),'command':list(map(str,argv)),'started_at':t,'ended_at':datetime.now(timezone.utc).isoformat(),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(json.dumps(records[-1]))
 return r
def ex(did,*cmd,check=True):return run(['docker','exec',did,*cmd],check)
def ssh(i,cmd,check=True,timeout=45):return run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-i',root/'private/freebsd/management_key','-p',22352+i,'root@127.0.0.1',cmd],check,timeout)
def hmp(i,command):
 path=root/'private/freebsd'/('monitor-v2-'+str(i)+'.sock');s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(2);s.connect(str(path));greeting=s.recv(4096).decode(errors='replace');s.sendall((command+'\n').encode());time.sleep(.2)
 try:result=s.recv(16384).decode(errors='replace')
 except socket.timeout:result=''
 s.close();records.append({'id':'hmp-%04d'%len(records),'command':['qemu-monitor',str(path),command],'returncode':0,'stdout':greeting+result,'stderr':''})
 if 'Error:' in result:raise RuntimeError(result)
try:
 for i in [0,1]:
  for cmd in ['sysctl net.inet.ipsec.debug=0','sysctl kern.crypto.allow_soft','kldstat','/usr/local/sbin/swanctl --load-all','/usr/local/sbin/swanctl --list-algs','/usr/local/sbin/swanctl --stats','uname -a','ifconfig -a','netstat -rn','ldd /usr/local/lib/ipsec/plugins/libstrongswan-botan.so','pkg info botan3','cat /usr/local/etc/swanctl/swanctl.conf']:ssh(i,cmd)
 for phase in ['before','after']:
  records.append({'id':'phase-'+phase,'command':['phase',phase],'returncode':0,'stdout':'','stderr':''})
  for i in [0,1]:
   for cmd in ['/usr/local/sbin/swanctl --list-sas','netstat -s -p esp','setkey -DP','netstat -rn']:ssh(i,cmd,check=False)
  for did in ['NC_O_A1','NC_O_B1']:ex(did,'swanctl','--list-sas');ex(did,'ip','-s','xfrm','state','list','nokeys')
  if phase=='before':
   for source,dest in [('NC_R_A1','10.2.1.10'),('NC_R_B1','10.1.1.10')]:
    r=ex(source,'ping','-n','-c','3','-W','1',dest,check=False);records[-1].update(probe='cross-OS-nested-data',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply' if r.returncode==1 else 'collection_error')
 for i in [0,1]:
  ssh(i,'/usr/local/sbin/swanctl --uninstall --child protected')
  ssh(i,'/usr/local/sbin/swanctl --terminate --ike msc',check=False)
 for source,dest in [('NC_R_A1','10.2.1.10'),('NC_R_B1','10.1.1.10')]:
  r=ex(source,'ping','-n','-c','3','-W','1',dest,check=False);records[-1].update(probe='FreeBSD-Inner-SA-loss',expected_result='no_reply',observed_result='delivered' if r.returncode==0 else 'no_reply' if r.returncode==1 else 'collection_error')
 for i in [0,1]:ssh(i,'/usr/local/sbin/swanctl --load-all')
 ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',timeout=90)
 for source,dest in [('NC_R_A1','10.2.1.10'),('NC_R_B1','10.1.1.10')]:
  r=ex(source,'ping','-n','-c','3','-W','1',dest,check=False);records[-1].update(probe='FreeBSD-Inner-SA-restored',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply' if r.returncode==1 else 'collection_error')
 for i in [0,1]:ssh(i,'/usr/local/sbin/swanctl --list-sas')
 for i in [0,1]:ssh(i,'cat /root/tdn-freebsd-v3/charon-runtime.log')
except Exception as e:error=str(e)
finally:
 data={'schema_version':'csfc-native-different-OS/v1','started_at':started,'ended_at':datetime.now(timezone.utc).isoformat(),'runtime_backend':'native-FRR-OVS-Linux-Outer-with-QEMU-FreeBSD-Inner','spec':spec,'records':records,'error':error,'scope':['Actual FreeBSD Inner kernels and Botan IKE cryptographic plugin replace only the two owned ND Inner containers. Native Linux Outers, FRR routing and OVS switching remain active.','Private test credential copying occurs entirely within pc22 and its guests; no private bytes enter these public artifacts.','Physical hardware remains shared in this case. Four-worker physical-role separation is a separate case.','Different OS and observed cryptographic implementation do not establish approved products, independent manufacturers/subsidiary relationships, or an NSA independence determination.','The guest management interface and virtualization host remain explicit trusted control infrastructure. No all-execution MAC confinement or non-bypass claim follows from finite traffic.']}
 (out/'observations.json').write_text(json.dumps(data,indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':'observations.json','sha256':hashlib.sha256((out/'observations.json').read_bytes()).hexdigest()}]},indent=2)+'\n')
 print(json.dumps({'error':error,'records':len(records),'probes':[r for r in records if 'probe' in r]}))
