import argparse,hashlib,json,os,shlex,signal,subprocess,time
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/aw-power-event-v5';out.mkdir();records=[];error=None;key=root/'private/freebsd/management_key'
def run(cmd,check=True,timeout=40):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=timeout);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if 'PRIVATE KEY-----'in r.stdout:raise RuntimeError('Secret export refused')
 if check and r.returncode:raise RuntimeError(r.stderr[-1000:])
 return r
def ssh(cmd,check=True,timeout=40):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=accept-new','-i',key,'-p','22224','freebsd@127.0.0.1',cmd],check,timeout)
def management(label):
 command="printf 'GET /status HTTP/1.0\\r\\nHost: managed.nd.test\\r\\n\\r\\n' | openssl s_client -quiet -verify_return_error -verify_hostname managed.nd.test -connect 172.28.97.2:443 -CAfile /home/freebsd/aw-case-v3/ca.pem -cert /home/freebsd/aw-case-v3/virtual-aw.pem -key /home/freebsd/aw-case-v3/virtual-aw.key -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384"
 r=ssh(command,False);records[-1].update(probe=label,expected_result='delivered',observed_result='delivered'if '200 OK'in r.stdout and r.stdout.endswith('ready')else'unexpected')
def poweroff(label):
 pid=int((root/'private/freebsd/aw-qemu-v3.pid').read_text());args=[x.decode()for x in Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')if x];assert '-name'in args and args[args.index('-name')+1]=='tcv3-virtual-aw-dedicated-host';os.kill(pid,signal.SIGTERM);deadline=time.monotonic()+20
 while Path('/proc/'+str(pid)).exists()and time.monotonic()<deadline:time.sleep(.5)
 assert not Path('/proc/'+str(pid)).exists(),'Owned AW did not power off'
 r=ssh('true',False,10);records[-1].update(probe=label,expected_result='powered-off',observed_result='powered-off'if r.returncode else'unexpected')
 return args
try:
 run(['hostname']);run(['cat','/sys/class/dmi/id/product_uuid'])
 ssh('cat /etc/start_if.vtnet1; ifconfig vtnet1; mount',False)
 management('AW-authenticated-management-before-power')
 marker='synthetic-aw-durable-marker-'+datetime.now(timezone.utc).isoformat();ssh('printf %s '+shlex.quote(marker)+' > /home/freebsd/aw-case-v3/power-marker; fsync /home/freebsd/aw-case-v3/power-marker; fsync /home/freebsd/aw-case-v3; sync; sleep 1; sha256 /home/freebsd/aw-case-v3/power-marker')
 args=poweroff('AW-unavailable-while-powered-off');run(args)
 deadline=time.monotonic()+180
 while time.monotonic()<deadline:
  r=ssh('uname -a',False,10)
  if r.returncode==0:break
  time.sleep(3)
 assert r.returncode==0,'AW restart did not become ready'
 ssh('ifconfig -a');r=ssh('sha256 /home/freebsd/aw-case-v3/power-marker');assert hashlib.sha256(marker.encode()).hexdigest()in r.stdout;records[-1].update(probe='AW-durable-marker-after-power',expected_result='preserved',observed_result='preserved')
 management('AW-authenticated-management-after-power')
 ssh('sync');poweroff('AW-final-unused-state-powered-off')
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'runtime_backend':'Actual FreeBSD virtual AW on dedicated pc16 workstation hardware','scope':['The owned AW QEMU process is positively identified by PID and exact configured name before power-off. Its recorded original argv restarts the same owned disk and interfaces. The physical AW host remains running.','A synthetic marked file is synced before an abrupt host-controlled guest power-off. Its hash and mutual-TLS management are checked after restart. The unused guest is left powered off.','The guest freebsd user is used as observed; no unsupported guest administrator privilege is asserted. Host root remains the explicit trusted laboratory power control. Actual personnel policy and long-term audit history remain external.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'probes':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
