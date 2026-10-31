import hashlib,json,shlex,socket,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-replay-20261024-v6');out=root/'exports/freebsd-automatic-reauth-v3';out.mkdir();private=root/'private/freebsd-native-creds';work=root/'private/freebsd-automatic-reauth-v3';work.mkdir(mode=0o700);records=[];started=datetime.now(timezone.utc).isoformat();error=None
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
def copy_guest(i,source,dest):
 return run(['scp','-q','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-i',root/'private/freebsd/management_key','-P',22352+i,source,'root@127.0.0.1:'+dest])
def reload(i):
 ssh(i,'/usr/local/sbin/swanctl --flush-certs',check=False)
 ssh(i,'/usr/local/sbin/swanctl --load-creds --clear')
 ssh(i,'/usr/local/sbin/swanctl --load-conns')
def stop():
 for i in [0,1]:
  ssh(i,'/usr/local/sbin/swanctl --uninstall --child protected',check=False)
  ssh(i,'/usr/local/sbin/swanctl --terminate --ike msc',check=False)
try:
 import re
 offsets={}
 for i in [0,1]:
  offsets[i]=int(ssh(i,'wc -l < /root/tdn-freebsd-v3/charon-runtime.log').stdout.strip())
  original=(private/('A' if i==0 else 'B')/'swanctl/swanctl.conf').read_text()
  config=re.sub(r'reauth_time\s*=\s*3h','reauth_time = '+('20s' if i==0 else '120s')+'\n  rand_time = 0s\n  over_time = 5s',original,count=1)
  config=re.sub(r'rekey_time\s*=\s*0s','rekey_time = '+('40s' if i==0 else '180s'),config,count=1)
  path=work/('scheduled-'+str(i)+'.conf');path.write_text(config);(out/('scheduled-'+str(i)+'.public.conf')).write_text(config)
  copy_guest(i,path,'/usr/local/etc/swanctl/swanctl.conf')
 stop()
 for i in [0,1]:ssh(i,'/usr/local/sbin/swanctl --load-all');ssh(i,'date -u')
 ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',timeout=90)
 for i in [0,1]:ssh(i,'/usr/local/sbin/swanctl --list-sas')
 jobs=[]
 for did,dest in [('NC_R_A1','10.2.1.10'),('NC_R_B1','10.1.1.10')]:
  cmd=['docker','exec',did,'ping','-n','-c','100','-i','0.5','-W','1',dest];jobs.append((cmd,datetime.now(timezone.utc).isoformat(),subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)))
 for cmd,begin,p in jobs:
  stdout,stderr=p.communicate(timeout=60);records.append({'command':cmd,'started_at':begin,'ended_at':datetime.now(timezone.utc).isoformat(),'returncode':p.returncode,'stdout':stdout,'stderr':stderr,'probe':'payload-during-automatic-reauth','expected_result':'delivered','observed_result':'delivered' if p.returncode==0 else 'no_reply'})
 for i in [0,1]:
  ssh(i,'/usr/local/sbin/swanctl --list-sas')
  ssh(i,'tail -n +'+str(offsets[i]+1)+' /root/tdn-freebsd-v3/charon-runtime.log')
except Exception as e:error=str(e)
finally:
 try:
  stop()
  for i in [0,1]:
   copy_guest(i,private/('A' if i==0 else 'B')/'swanctl/swanctl.conf','/usr/local/etc/swanctl/swanctl.conf')
   ssh(i,'/usr/local/sbin/swanctl --load-all')
  ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',check=False,timeout=90)
  r=ex('NC_R_A1','ping','-n','-c','3','-W','1','10.2.1.10',check=False);records[-1].update(probe='original-timers-restored',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply')
 except Exception as e:
  if error is None:error=str(e)
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['A real scheduled timer experiment in only the owned FreeBSD ND Inner guests. Initiator reauth20s, IKErekey40s, rand0, over5; peer reauth120s/rekey180s avoids simultaneous initial timer. Two overlapping100-packet bidirectional streams span50seconds.','Public interval-specific daemon lines preserve authentication/new-SA/deletion ordering; configured IKE reauthentication is scheduled before pure IKErekey. A successful scheduled reauthentication replaces the SA and resets its rekey timer, so a pure IKErekey need not occur.','The experiment establishes finite scheduled behavior, not every possible manual rekey or all-time enforcement. Original reauth3h/rekey0 configurations and useful traffic are restored in finally.']},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error,'probes':[{k:r[k] for k in ['probe','expected_result','observed_result']} for r in records if 'probe'in r]}))
