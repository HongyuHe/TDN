import hashlib,json,shlex,socket,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-replay-20261024-v7');out=root/'exports/native-DNS-hardening-v7';out.mkdir();private=root/'private/freebsd-native-creds';private.mkdir(mode=0o700,exist_ok=True);records=[];started=datetime.now(timezone.utc).isoformat();error=None
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
try:
 devices=[d['id'] for d in spec['devices'] if not d['id'].startswith(('NQ_I_','NQ_R_'))]
 for did in devices:
  for cmd in [['cat','/etc/resolv.conf'],['cat','/etc/nsswitch.conf'],['iptables-save','-c'],['ps','-eo','pid,comm']]:ex(did,*cmd,check=False)
  program="from pathlib import Path;import re;p=Path('/etc/nsswitch.conf');s=p.read_text();s=re.sub(r'(?m)^hosts:.*$', 'hosts: files',s);p.write_text(s);Path('/etc/resolv.conf').write_text('')"
  pid=run(['docker','inspect','--format','{{.State.Pid}}',did]).stdout.strip()
  originally_ro=run(['docker','inspect','--format','{{.HostConfig.ReadonlyRootfs}}',did]).stdout.strip()=='true'
  enter=['nsenter','--target',pid,'--mount','--pid','--root','--wd=/','--']
  run(enter+['python3','-c',"import ctypes,os;l=ctypes.CDLL(None,use_errno=True);r=l.mount(None,b'/',None,4096+32+2097152,None);assert r==0,os.strerror(ctypes.get_errno());r=l.mount(None,b'/etc/resolv.conf',None,4096+32+2097152,None);assert r==0,os.strerror(ctypes.get_errno());print('readonly=',bool(os.statvfs('/').f_flag&os.ST_RDONLY))"])
  try:ex(did,'python3','-c',program)
  finally:run(enter+['python3','-c',"import ctypes,os;l=ctypes.CDLL(None,use_errno=True);flags=4096+32+2097152+"+str(int(originally_ro))+";r=l.mount(None,b'/etc/resolv.conf',None,flags,None);assert r==0,os.strerror(ctypes.get_errno());r=l.mount(None,b'/',None,flags,None);assert r==0,os.strerror(ctypes.get_errno());print('readonly=',bool(os.statvfs('/').f_flag&os.ST_RDONLY))"])
  run(['head','-1','/proc/'+pid+'/mountinfo'])

  for protocol in ['udp','tcp']:
   if ex(did,'iptables','-C','OUTPUT','-p',protocol,'--dport','53','-j','REJECT',check=False).returncode:ex(did,'iptables','-I','OUTPUT','1','-p',protocol,'--dport','53','-j','REJECT')
  for cmd in [['cat','/etc/resolv.conf'],['cat','/etc/nsswitch.conf'],['getent','hosts','www.example.com']]:ex(did,*cmd,check=False)
  dns="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1);q=bytes.fromhex('6d310100000100000000000003777777076578616d706c6503636f6d0000010001');s.sendto(q,('127.0.0.11',53));print(s.recvfrom(2048)[1])"
  r=ex(did,'python3','-c',dns,check=False);records[-1].update(probe='component-DNS-egress-disabled',expected_result='rejected-or-no-reply',observed_result='collection_error' if r.returncode==127 else 'rejected-or-no-reply' if r.returncode else 'unexpected-reply')
  ex(did,'iptables-save','-c')
 for i in [0,1]:
  for cmd in ['cat /etc/resolv.conf','cat /etc/nsswitch.conf','pfctl -sr -v','ps -axo pid,comm']:ssh(i,cmd,check=False)
  program="sed -i '' -E 's/^hosts:.*/hosts: files/' /etc/nsswitch.conf; : > /etc/resolv.conf; sysrc nuageinit_enable=NO"
  ssh(i,program)
  pf='set block-policy return\nblock return out quick proto { tcp, udp } from self to any port 53\n'
  ssh(i,'printf %s '+shlex.quote(pf)+' > /root/tdn-freebsd-v3/dns-hardening.pf')
  ssh(i,'kldload pf',check=False);ssh(i,'pfctl -f /root/tdn-freebsd-v3/dns-hardening.pf');ssh(i,'pfctl -e',check=False)
  ssh(i,'install -m600 /root/tdn-freebsd-v3/dns-hardening.pf /etc/pf.conf');ssh(i,'sysrc pf_enable=YES')
  for cmd in ['cat /etc/resolv.conf','cat /etc/nsswitch.conf','pfctl -sr -vv','sysrc pf_enable nuageinit_enable','getent hosts www.example.com']:ssh(i,cmd,check=False)
  r=ssh(i,'timeout 4 drill @10.0.2.3 www.example.com',check=False);records[-1].update(probe='FreeBSD-component-DNS-egress-disabled',expected_result='rejected-or-no-reply',observed_result='collection_error' if r.returncode==127 else 'rejected-or-no-reply' if r.returncode else 'unexpected-reply')
  ssh(i,'pfctl -sr -vv')
 r=ex('NQ_R_A1','ping','-n','-c','3','-W','1','10.2.1.10',check=False);records[-1].update(probe='protected-data-after-DNS-disable',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply')
except Exception as e:error=str(e)
finally:
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['The selected owned ND profile network devices disable libc DNSlookup via hosts-files-only NSS and empty resolver files. Native Linux device OUTPUT rules and FreeBSD PF source-self rules reject component DNS egress while forwarded Red traffic remains separately scoped.','Explicit specified DNS servers already satisfy the alternative in thresholdMSC-SR-20; these changes exercise optionalobjectiveMSC-SR-19. No baseline threshold violation is inferred just from a configured resolver.','FreeBSD local NoCloud service is disabled for subsequent boot, using retained static interface configuration. No arbitrary remote bootconfiguration service or TFTP use is inferred from local ISO provisioning.','These concrete configurations and finite DNS/traffic controls do not establish every possible program behavior, host Docker/root confinement, approved service inventory or every startup/default-account requirement.']},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error,'probes':[{k:r[k] for k in ['probe','expected_result','observed_result']} for r in records if 'probe'in r]}))
