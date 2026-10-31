import hashlib,json,shlex,socket,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-replay-20261024-v7');out=root/'exports/independent-Red-clocks-v3';out.mkdir();private=root/'private/freebsd-native-creds';private.mkdir(mode=0o700,exist_ok=True);records=[];started=datetime.now(timezone.utc).isoformat();error=None
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
nodes=[];processes=[]
try:
 server='''import socket,struct,time,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],123))
def stamp(t):
 x=t+2208988800
 return struct.pack("!II",int(x),int((x%1)*2**32))
while True:
 data,addr=s.recvfrom(1024)
 if len(data)<48:continue
 received=time.time();r=bytearray(48);r[0]=36;r[1]=2;r[2]=4;r[3]=236;r[12:16]=b"LOCL";r[16:24]=stamp(received);r[24:32]=data[40:48];r[32:40]=stamp(received);r[40:48]=stamp(time.time());s.sendto(r,addr)
'''
 path=out/'ntp-server.py';path.write_text(server)
 for i in [0,1]:
  node='tcv3-clock-'+str(i);nodes.append(node);run(['ip','netns','add',node])
  host='nt3h'+str(i);peer='nt3p'+str(i);bridge='nq3b'+str(i*2)
  run(['ip','link','add',host,'type','veth','peer','name',peer]);run(['ip','link','set',host,'master',bridge]);run(['ip','link','set',host,'up']);run(['ip','link','set',peer,'netns',node])
  addr='10.'+str(i+1)+'.1.20'
  for cmd in [['ip','link','set','lo','up'],['ip','link','set',peer,'up'],['ip','addr','add',addr+'/24','dev',peer]]:run(['ip','netns','exec',node,*cmd])
  processes.append(subprocess.Popen(['ip','netns','exec',node,'python3',str(path),addr],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
  ssh(i,'sysctl kern.timecounter.hardware; uname -a; ntpdate --version',check=False)
  ssh(i,'ntpdate -q -u '+addr)
  ssh(i,'date -u -f %s $(($(date -u +%s)+2))')
  ssh(i,'ntpdate -q -u '+addr)
  r=ssh(i,'ntpdate -b -u '+addr,check=False)
  records[-1].update(probe='independent-guest-clock-step',expected_result='clock-adjusted',observed_result='clock-adjusted' if r.returncode==0 and 'step time server' in r.stdout+r.stderr else 'unexpected')
  ssh(i,'ntpdate -q -u '+addr)
  run(['ip','-j','-d','link','show',host]);ssh(i,'ifconfig vtnet2; netstat -rn')
 r=ex('NQ_R_A1','ping','-n','-c','3','-W','1','10.2.1.10',check=False);records[-1].update(probe='protected-data-after-guest-clock-sync',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply')
except Exception as e:error=str(e)
finally:
 for p in processes:p.terminate();p.wait(timeout=3)
 for node in nodes:run(['ip','netns','delete',node],check=False)
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'runtime_backend':'native-ND-with-actual-FreeBSD-Inner-kernels-and-supplemental-Red-time-server-namespaces','scope':['Two actual FreeBSD Inner guest kernels query and synchronize to explicit local time sources on their own Red segments. Each guest clock is moved forward by two seconds before ntpdate performs a measured correction. Linux host clocks and unrelated workloads are never adjusted.','Separate guest kernels provide independent system-clock state even though they share physical KVM infrastructure. Kernel clock source, server source/address, time samples and actual adjustment diagnostics are retained.','Laboratory time sources use the host clock and have no supplied organizational trust or authoritative time-service approval. No Gray Outer synchronization or all-future drift bound is inferred. The temporary supplemental time server namespaces are cleaned after collection.']},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error,'probes':[{k:r[k] for k in ['probe','expected_result','observed_result']} for r in records if 'probe' in r]}))
