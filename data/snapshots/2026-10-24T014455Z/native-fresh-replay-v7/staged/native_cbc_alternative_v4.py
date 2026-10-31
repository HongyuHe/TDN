import hashlib,json,shlex,socket,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-replay-20261024-v7');out=root/'exports/native-CBC-alternative-v4';out.mkdir();private=root/'private/freebsd-native-creds';work=root/'private/native-CBC-alternative-v4';work.mkdir(mode=0o700);records=[];started=datetime.now(timezone.utc).isoformat();error=None
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
original_outer={}
def outer_reload():
 for did in ['NQ_O_A1','NQ_O_B1']:
  ex(did,'swanctl','--uninstall','--child','protected',check=False);ex(did,'swanctl','--terminate','--ike','msc',check=False);ex(did,'swanctl','--load-all')
def write_outer(did,config):
 mounts=json.loads(run(['docker','inspect','--format','{{json .Mounts}}',did]).stdout)
 mount=next(x for x in mounts if x['Destination']=='/etc/swanctl')
 path=Path(mount['Source'])/'swanctl.conf'
 assert path.is_relative_to(root/'private/native-replay-v7/devices')
 path.write_text(config)
 records.append({'command':['write-owned-public-configuration',str(path)],'returncode':0,'stdout':config,'stderr':''})

try:
 for did in ['NQ_O_A1','NQ_O_B1']:original_outer[did]=ex(did,'cat','/etc/swanctl/swanctl.conf').stdout
 stop()
 for i in [0,1]:
  original=(private/('A' if i==0 else 'B')/'swanctl/swanctl.conf').read_text();config=original.replace('aes256gcm16-prfsha384-ecp384','aes256-sha384-prfsha384-ecp384').replace('aes256gcm16-ecp384','aes256-sha384-ecp384')
  path=work/('inner-'+str(i)+'.conf');path.write_text(config);(out/('inner-'+str(i)+'.public.conf')).write_text(config);copy_guest(i,path,'/usr/local/etc/swanctl/swanctl.conf')
 for did,original in original_outer.items():
  config=original.replace('aes256gcm16-prfsha384-ecp384','aes256-sha384-prfsha384-ecp384').replace('aes256gcm16-ecp384','aes256-sha384-ecp384');write_outer(did,config)
 outer_reload();ex('NQ_O_A1','swanctl','--initiate','--child','protected')
 for i in [0,1]:ssh(i,'/usr/local/sbin/swanctl --load-all')
 ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',timeout=90)
 for phase in ['before','after']:
  records.append({'command':['phase',phase],'returncode':0,'stdout':'','stderr':''})
  for i in [0,1]:ssh(i,'/usr/local/sbin/swanctl --list-sas');ssh(i,'setkey -DP',check=False)
  for did in ['NQ_O_A1','NQ_O_B1']:ex(did,'swanctl','--list-sas');ex(did,'ip','-s','xfrm','state','list','nokeys')
  if phase=='before':
   for did,dest in [('NQ_R_A1','10.2.1.10'),('NQ_R_B1','10.1.1.10')]:
    r=ex(did,'ping','-n','-c','3','-W','1',dest,check=False);records[-1].update(probe='two-layer-CBC-AES256-SHA384',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply')
 stop()
 r=ex('NQ_R_A1','ping','-n','-c','3','-W','1','10.2.1.10',check=False);records[-1].update(probe='CBC-Inner-SA-loss',expected_result='no_reply',observed_result='delivered' if r.returncode==0 else 'no_reply')
except Exception as e:error=str(e)
finally:
 try:
  stop()
  for did,config in original_outer.items():write_outer(did,config)
  outer_reload();ex('NQ_O_A1','swanctl','--initiate','--child','protected',check=False)
  for i in [0,1]:
   copy_guest(i,private/('A' if i==0 else 'B')/'swanctl/swanctl.conf','/usr/local/etc/swanctl/swanctl.conf');ssh(i,'/usr/local/sbin/swanctl --load-all')
  ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',check=False,timeout=90)
  r=ex('NQ_R_A1','ping','-n','-c','3','-W','1','10.2.1.10',check=False);records[-1].update(probe='original-GCM-profile-restored',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply')
 except Exception as e:
  if error is None:error=str(e)
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['Fresh owned ND profile temporarily selects AES256-CBC/HMAC-SHA384 for IKE/ESP in both native Linux Outers and actual FreeBSD Inners, with P384 key establishment/certificates. Native FRR/OVS stay active.','Public loaded configurations, effective negotiated SAs and before/after counters must support the alternative; a configured string alone is insufficient.','Original GCM configurations and useful traffic are restored at completion. Finite behavior does not establish product approval or every CNSA profile clause.']},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error,'probes':[{k:r[k] for k in ['probe','expected_result','observed_result']} for r in records if 'probe'in r]}))
