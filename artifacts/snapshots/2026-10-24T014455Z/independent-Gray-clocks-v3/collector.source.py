import argparse,hashlib,json,shlex,subprocess,time
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--config',required=True);a=p.parse_args();config=json.loads(Path(a.config).read_text());root=Path(config['run_root']);out=root/'exports/independent-Gray-clocks-v3';out.mkdir();records=[];error=None;nodes=[];processes=[]
def run(cmd,check=True,timeout=30):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=timeout);records.append({'id':'gray-time-%04d'%len(records),'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr[-1000:]+r.stdout[-1000:])
 return r
def ssh(i,cmd,check=True):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-i',root/'private/freebsd/management_key','-p',22452+i,'root@127.0.0.1',cmd],check)
try:
 server="""import socket,struct,time,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],123))
def stamp(t):
 x=t+2208988800
 return struct.pack("!II",int(x),int((x%1)*2**32))
while True:
 data,addr=s.recvfrom(1024)
 if len(data)<48:continue
 received=time.time();r=bytearray(48);r[0]=36;r[1]=2;r[2]=4;r[3]=236;r[12:16]=b"LOCL";r[16:24]=stamp(received);r[24:32]=data[40:48];r[32:40]=stamp(received);r[40:48]=stamp(time.time());s.sendto(r,addr)
"""
 (out/'ntp-server.py').write_text(server)
 for i in [0,1]:
  node='tcv3-graytime-'+str(i);nodes.append(node);run(['ip','netns','add',node]);host='gt3h'+str(i);peer='gt3p'+str(i);bridge='lc3b'+str(2*i);addr='10.'+str(i+1)+'00.1.20';outer='10.'+str(i+1)+'00.1.1'
  run(['ip','link','add',host,'type','veth','peer','name',peer]);run(['ip','link','set',host,'master',bridge]);run(['ip','link','set',host,'up']);run(['ip','link','set',peer,'netns',node])
  for cmd in [['ip','link','set','lo','up'],['ip','link','set',peer,'up'],['ip','address','add',addr+'/24','dev',peer]]:run(['ip','netns','exec',node,*cmd])
  processes.append(subprocess.Popen(['ip','netns','exec',node,'python3',str(out/'ntp-server.py'),addr],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
  for cmd in ['iptables -A OUTPUT -o gray -s '+outer+' -d '+addr+' -p udp --dport 123 -j ACCEPT','iptables -A INPUT -i gray -s '+addr+' -d '+outer+' -p udp --sport 123 -j ACCEPT','iptables-save -c','cat /proc/sys/kernel/random/boot_id','uname -a','readlink /proc/self/ns/time','timedatectl status','ntpdate --version']:ssh(i,cmd,False)
  ssh(i,'ntpdate -q -u '+addr)
  ssh(i,'date -u -s @$(($(date -u +%s)+2))')
  ssh(i,'ntpdate -q -u '+addr)
  r=ssh(i,'ntpdate -b -u '+addr,False);records[-1].update(probe='actual-independent-Gray-Outer-clock-step',expected_result='clock-adjusted',observed_result='clock-adjusted'if r.returncode==0 else'unexpected')
  ssh(i,'ntpdate -q -u '+addr)
  ssh(i,'ip -j address show gray; ip -j route; swanctl --list-sas; ip -s xfrm state list nokeys')
 r=run(['docker','exec',config['device_prefix']+'_R_A1','ping','-n','-c','3','-W','1','10.2.1.10'],False);records[-1].update(probe='protected-data-after-Gray-clock-sync',expected_result='delivered',observed_result='delivered'if r.returncode==0 else'no_reply')
except Exception as e:error=str(e)
finally:
 for p in processes:p.terminate();p.wait(timeout=3)
 for node in nodes:run(['ip','netns','delete',node],False)
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'configuration':config,'records':records,'error':error,'runtime_backend':'Native FRR/OVS with actual Debian Linux Outer and FreeBSD Inner kernels','scope':['Two distinct Linux guest kernel clocks query and correct against separate explicit Gray-side test sources. Host clocks are never changed. Public boot IDs and actual kernel identities bind the clock observations.','Each Outer has explicit Gray source/destination/UDP port permits for its time server, alongside recorded data-plane filters and explicit trusted laboratory SSH control. Useful nested protected traffic is checked after correction.','The laboratory servers use the shared worker clock. Actual time-source approval, authentication, long-term drift and organizational time policy remain separate. The technical guest clock correction is independent from approval of the selected authority.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'probes':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
