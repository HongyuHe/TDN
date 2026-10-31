import argparse,hashlib,json,os,shlex,signal,socket,subprocess,time
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--output',required=True);a=p.parse_args();config=json.loads(Path(a.config).read_text());root=Path(config['run_root']);out=Path(a.output);out.mkdir();records=[];error=None;prefix=config['device_prefix'];key=root/'private/freebsd/management_key'
def run(cmd,check=True,timeout=45):
 begin=datetime.now(timezone.utc).isoformat();r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=timeout)
 if '-----BEGIN PRIVATE KEY-----'in r.stdout:raise RuntimeError('Secret export refused')
 records.append({'id':'power-%04d'%len(records),'started_at':begin,'ended_at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr[-2000:])
 return r
def ssh(i,cmd,check=True,timeout=45):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=accept-new','-i',key,'-p',str(config['ssh_port_base']+i),'root@127.0.0.1',cmd],check,timeout)
def probe(expect,label):
 r=run(['docker','exec',prefix+'_R_A1','ping','-n','-c','3','-W','1','10.2.1.10'],False)
 records[-1].update(probe=label,expected_result=expect,observed_result='delivered'if r.returncode==0 else 'no_reply'if r.returncode==1 else 'collection_error')
def ensure_protected():
 r=ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',False,timeout=90)
 if r.returncode:
  assert 'due to existing duplicate' in r.stdout,'CHILD initiation failed without a recorded installed duplicate'
  installed=ssh(0,'/usr/local/sbin/swanctl --list-sas')
  assert 'INSTALLED' in installed.stdout and 'protected:' in installed.stdout,'No installed protected CHILD observed'
rc="""#!/bin/sh
# PROVIDE: tdn_gateway
# REQUIRE: NETWORKING
# KEYWORD: shutdown
. /etc/rc.subr
name=tdn_gateway
rcvar=tdn_gateway_enable
start_cmd=tdn_gateway_start
stop_cmd=tdn_gateway_stop
tdn_gateway_start()
{
 /sbin/kldstat -n ipsec >/dev/null 2>&1 || /sbin/kldload ipsec
 /sbin/sysctl kern.crypto.allow_soft=1
 /sbin/route delete default >/dev/null 2>&1 || true
 /usr/bin/printf 'gateway-start %s\\n' "$(/bin/date -u +%FT%TZ)" >> /var/log/tdn-lifecycle.log
 /usr/sbin/daemon -o /var/log/tdn-charon.log -p /var/run/tdn-charon.pid /usr/local/libexec/ipsec/charon
 n=0
 while test "$n" -lt 20; do
  /usr/local/sbin/swanctl --load-all && return 0
  n=$((n+1))
  /bin/sleep 1
 done
 return 1
}
tdn_gateway_stop()
{
 if test -s /var/run/tdn-charon.pid; then
  /bin/kill "$(cat /var/run/tdn-charon.pid)" || true
 fi
}
load_rc_config "$name"
: "$tdn_gateway_enable"
run_rc_command "$1"
"""
try:
 (out/'tdn_gateway.rc').write_text(rc)
 spec=json.loads((root/'scripts/profiles'/(config['profile_name']+'.json')).read_text())
 for i in [0,1]:
  site=i+1;peer=2-i
  for cmd in ['cat /etc/rc.conf','cat /etc/sysctl.conf','kldstat -n ipsec','ifconfig -a','netstat -rn']:
   ssh(i,cmd,False)
  settings={'sshd_enable':'YES','ifconfig_vtnet0':'SYNCDHCP','gateway_enable':'YES','nuageinit_enable':'NO','ifconfig_vtnet1':'down','ifconfig_vtnet2':'inet 10.'+str(site)+'.1.1/24 mtu 1320','ifconfig_vtnet3':'inet 10.'+str(site)+'00.1.2/24 mtu 1400','static_routes':'tdn_red tdn_gray','route_tdn_red':'-net 10.'+str(peer)+'.1.0/24 10.'+str(site)+'00.1.1','route_tdn_gray':'-host 10.'+str(peer)+'00.1.2 10.'+str(site)+'00.1.1','tdn_gateway_enable':'YES'}
  for k,v in settings.items():ssh(i,'sysrc '+shlex.quote(k+'='+v))
  ssh(i,'sysrc kld_list+=ipsec')
  ssh(i,"grep -q '^kern.crypto.allow_soft=1$' /etc/sysctl.conf || printf '%s\\n' kern.crypto.allow_soft=1 >> /etc/sysctl.conf")
  ssh(i,'printf %s '+shlex.quote(rc)+' > /usr/local/etc/rc.d/tdn_gateway; chmod 555 /usr/local/etc/rc.d/tdn_gateway')
  ssh(i,'fsync /etc/rc.conf; fsync /etc/sysctl.conf; fsync /usr/local/etc/rc.d/tdn_gateway; fsync /etc; fsync /usr/local/etc/rc.d; sync; wc -c /etc/rc.conf /usr/local/etc/rc.d/tdn_gateway')
  marker='synthetic-durable-marker-'+str(i)+'-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
  ssh(i,'cat /etc/syslog.conf; ps -axo pid,comm | grep syslogd')
  ssh(i,'logger -p auth.notice -t tdn-audit '+shlex.quote(marker)+'; n=0; while ! grep -F '+shlex.quote(marker)+' /var/log/auth.log; do n=$((n+1)); test "$n" -lt 10 || exit 1; sleep 1; done; fsync /var/log/auth.log; fsync /var/log; sync')
  records[-1]['scope']='Actual syslogd authentication-facility audit event, flushed by file and directory fsync before the guest power event.'
  oldpid=int((root/'private/freebsd'/('qemu-v2-'+str(i)+'.pid')).read_text())
  argv=Path('/proc/'+str(oldpid)+'/cmdline').read_bytes().split(b'\0');argv=[x.decode()for x in argv if x]
  assert argv[0].endswith('qemu-system-x86_64') and str(root/'private/freebsd')in ' '.join(argv)
  for j,zone in enumerate(['red','gray']):
   device=next(d for d in spec['devices']if d['id']==prefix+'_I_'+('A'if i==0 else'B')+'1')
   #* The stopped native container retains the assigned MAC in its public inspect metadata.
   #* Native integration recorded the old interface MAC before replacement.
   original=json.loads((root/'exports/freebsd-native-integration-v3/observations.json').read_text())
   iface_records=[r for r in original['records']if r.get('command')==['docker','exec',device['id'],'ip','-j','-d','address']]
   interfaces=json.loads(iface_records[0]['stdout']);mac=next(x['address']for x in interfaces if x['ifname']==zone)
   netid=config['bridge_prefix']+zone
   if any(('tap,id='+netid+',')in arg for arg in argv):continue
   argv+=['-netdev','tap,id='+netid+',ifname='+config['bridge_prefix']+'t'+str(2*i+j)+',script=no,downscript=no','-device','virtio-net-pci,netdev='+netid+',mac='+mac]
  records.append({'id':'restart-argv-'+str(i),'command':argv,'scope':'Actual initial QEMU command plus both recorded hot-plugged native data NICs. Private disk and key path names are metadata; private bytes are not exported.'})
  ensure_protected()
  probe('delivered','protected-before-poweroff-'+str(i))
  records.append({'id':'abrupt-stop-'+str(i),'at':datetime.now(timezone.utc).isoformat(),'pid':oldpid,'signal':'SIGTERM','scope':'The positively identified owned QEMU process stops without guest shutdown. Host hardware remains running.'})
  os.kill(oldpid,signal.SIGTERM)
  deadline=time.monotonic()+90
  while Path('/proc/'+str(oldpid)).exists()and time.monotonic()<deadline:time.sleep(1)
  assert not Path('/proc/'+str(oldpid)).exists(),'Guest poweroff did not exit the positively identified owned QEMU process'
  records.append({'id':'poweroff-'+str(i),'at':datetime.now(timezone.utc).isoformat(),'old_qemu_pid':oldpid,'process_exists':False})
  probe('no_reply','protected-during-Inner-poweroff-'+str(i))
  run(argv,timeout=30)
  deadline=time.monotonic()+180
  while time.monotonic()<deadline:
   r=ssh(i,'test -S /var/run/charon.vici && /usr/local/sbin/swanctl --stats',False,timeout=12)
   if r.returncode==0:break
   time.sleep(3)
  assert r.returncode==0,'Persistent startup did not become ready'
  r=ssh(i,'grep -F '+shlex.quote(marker)+' /var/log/auth.log');assert marker in r.stdout
  records[-1].update(probe='syslog-audit-event-after-power-'+str(i),expected_result='preserved',observed_result='preserved')
  for cmd in ['cat /etc/rc.conf','cat /etc/sysctl.conf','kldstat -n ipsec','ifconfig -a','netstat -rn','cat /var/log/tdn-lifecycle.log','/usr/local/sbin/swanctl --list-algs']:ssh(i,cmd,False)
  ensure_protected()
  probe('delivered','protected-after-Inner-poweron-'+str(i))
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
 (out/'observations.json').write_text(json.dumps({'started_config':config,'ended_at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'runtime_backend':'Native FRR/OVS with actual FreeBSD Inner guests, persistent rc.d startup and owned guest power cycles','scope':['Only the two owned guest QEMU processes are power-cycled. Shared Linux hosts and unrelated workloads remain active.','Persistent kernel module, interface, route, IP forwarding and charon settings are recorded. Readiness and useful nested traffic are checked after reboot.','The selected tests explicitly fsync an actual syslogd audit record before an abrupt owned guest stop and test its survival after restart. The per-probe outcomes determine success. Lifecycle and startup observations demonstrate the selected bounded continuation. No one-year retention, quarter audit, agency adoption, arbitrary power failure or hardware firmware assurance is inferred.']},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error,'probes':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
