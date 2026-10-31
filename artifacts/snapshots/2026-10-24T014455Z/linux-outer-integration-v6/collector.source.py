import argparse,hashlib,json,shlex,socket,subprocess,time
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--config',required=True);a=p.parse_args();config=json.loads(Path(a.config).read_text());root=Path(config['run_root']);out=root/'exports/linux-outer-integration-v6';out.mkdir();private=root/'private/linux-outer-creds';private.mkdir(mode=0o700,exist_ok=True);records=[];error=None;prefix=config['device_prefix'];spec=json.loads((root/'scripts/profiles'/(config['profile_name']+'.json')).read_text())
def run(cmd,check=True,timeout=45):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=timeout)
 if 'PRIVATE KEY-----'in r.stdout:raise RuntimeError('Secret export refused')
 records.append({'id':'linux-%04d'%len(records),'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr[-2000:])
 return r
def ssh(i,cmd,check=True,timeout=45):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=accept-new','-i',root/'private/freebsd/management_key','-p',22452+i,'root@127.0.0.1',cmd],check,timeout)
def ex(did,*cmd,check=True):return run(['docker','exec',did,*cmd],check)
def hmp(i,command):
 path=root/'private/linux-outer'/('monitor-'+str(i)+'.sock');s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(2);s.connect(str(path));greeting=s.recv(4096).decode(errors='replace');s.sendall((command+'\n').encode());time.sleep(.3)
 try:result=s.recv(16384).decode(errors='replace')
 except socket.timeout:result=''
 s.close();records.append({'id':'hmp-%04d'%len(records),'command':['qemu-monitor',str(path),command],'stdout':greeting+result})
 if 'Error:'in result:raise RuntimeError(result)
try:
 for i in [0,1]:
  deadline=time.monotonic()+1200
  while time.monotonic()<deadline:
   r=ssh(i,'test -f /root/tdn-linux-outer-ready && test -x /usr/lib/ipsec/charon',False,12)
   if r.returncode==0:break
   time.sleep(5)
  assert r.returncode==0,'Linux Outer preparation not ready'
  for cmd in ['uname -a','cat /etc/os-release','cat /proc/sys/kernel/random/boot_id','swanctl --version','openssl version','ip -j -d address']:ssh(i,cmd,False)
 initial=json.loads((root/'exports/linux-outer-integration-v3/observations.json').read_text())['initial_public_identities']
 for i,site in enumerate(['A','B']):
  did=prefix+'_O_'+site+'1';d=private/site;d.mkdir(mode=0o700,exist_ok=True)
  if not (d/'swanctl').exists():run(['docker','cp',did+':/etc/swanctl',d])
  filters=(root/'exports/linux-outer-integration-v3'/(site+'.iptables.public')).read_text() if site=='A' else ex(did,'iptables-save').stdout;(out/(site+'.iptables.public')).write_text(filters)
  ssh(i,'mkdir -p /etc/swanctl')
  run(['scp','-qr','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-i',root/'private/freebsd/management_key','-P',22452+i,d/'swanctl','root@127.0.0.1:/etc/'])
  run(['docker','stop','-t','3',did])
  for j,zone in enumerate(['gray','black']):
   peer=prefix+('_G_'if zone=='gray'else'_OF_')+site+'1';peerif='outer'if zone=='gray'else'inside';old=next(x for x in initial[peer]['interfaces']if x['ifname']==peerif);outer=next(x for x in initial[did]['interfaces']if x['ifname']==zone);pid=initial[peer]['pid']
   existing=(site=='A')
   if not existing:assert ex(peer,'ip','link','show',peerif,check=False).returncode!=0,'Refuse replacing a live peer endpoint'
   index=2*i+j;bridge='lc3b'+str(index);tap='lc3t'+str(index);host='lc3h'+str(index);port='lc3p'+str(index)
   if not existing:
    run(['ip','link','add',bridge,'type','bridge','stp_state','0']);run(['ip','link','set',bridge,'up']);run(['ip','tuntap','add','dev',tap,'mode','tap']);run(['ip','link','set',tap,'master',bridge]);run(['ip','link','set',tap,'up']);run(['ip','link','add',host,'type','veth','peer','name',port]);run(['ip','link','set',host,'master',bridge]);run(['ip','link','set',host,'up']);run(['ip','link','set',port,'netns',pid]);run(['nsenter','-t',pid,'-n','ip','link','set',port,'name',peerif]);ex(peer,'ip','link','set',peerif,'address',old['address'],'mtu',old['mtu'],'up')
    for addr in old.get('addr_info',[]):
     if addr['family']=='inet':ex(peer,'ip','address','replace',addr['local']+'/'+str(addr['prefixlen']),'dev',peerif)
    for route in next(x for x in spec['devices']if x['id']==peer).get('routes',[]):ex(peer,'ip','route','replace',route['prefix'],'via',route['via'])
    netid='lc3'+zone;hmp(i,'netdev_add tap,id='+netid+',ifname='+tap+',script=no,downscript=no');hmp(i,'device_add virtio-net-pci,id='+netid+'nic,netdev='+netid+',mac='+outer['address'])
   time.sleep(.5)
   rename="import json,subprocess;v=json.loads(subprocess.check_output(['ip','-j','link']));n=next(x['ifname']for x in v if x.get('address')=="+repr(outer['address'])+");subprocess.run(['ip','link','set',n,'name',"+repr(zone)+"],check=True)"
   ssh(i,'python3 -c '+shlex.quote(rename));ssh(i,'ip link set '+zone+' mtu '+str(outer['mtu'])+' up')
   for addr in outer.get('addr_info',[]):
    if addr['family']=='inet':ssh(i,'ip address replace '+addr['local']+'/'+str(addr['prefixlen'])+' dev '+zone)
  ssh(i,'sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0')
  ssh(i,'ip route del default',False)
  for route in next(x for x in spec['devices']if x['id']==did).get('routes',[]):ssh(i,'ip route replace '+route['prefix']+' via '+route['via'])
  control='-A INPUT -i ens3 -p tcp --dport 22 -j ACCEPT\n-A OUTPUT -o ens3 -p tcp --sport 22 -j ACCEPT\n'
  mgmt=json.loads(ssh(i,'ip -j route get 10.0.2.2').stdout)[0]['dev'];control=control.replace('ens3',mgmt)
  filters=filters.replace('COMMIT\n',control+'COMMIT\n')
  (out/(site+'.iptables.effective.public')).write_text(filters)
  ssh(i,'ss -ntp; ip -j route get 10.0.2.2; printf %s '+shlex.quote(filters)+' | iptables-restore')
  conf='charon {\n install_routes = no\n load_modular = yes\n plugins {\n include strongswan.d/charon/*.conf\n }\n}\ninclude strongswan.d/*.conf\n'
  ssh(i,'printf %s '+shlex.quote(conf)+' > /etc/strongswan.conf')
  ssh(i,'/usr/lib/ipsec/charon >/var/log/tdn-outer-charon.log 2>&1 </dev/null &')
  time.sleep(.5);ssh(i,'swanctl --load-all')
  for cmd in ['ip -j -d address','ip -4 rule show','ip -4 route show table all','iptables-save -c','swanctl --list-algs','swanctl --stats','ldd /usr/lib/ipsec/plugins/libstrongswan-openssl.so','sha256sum /usr/lib/ipsec/plugins/libstrongswan-openssl.so']:ssh(i,cmd,False)
 ssh(0,'swanctl --initiate --child protected',timeout=90)
 for phase in ['before','after']:
  for i in [0,1]:
   for cmd in ['swanctl --list-sas','ip -s xfrm state list nokeys','ip xfrm policy']:ssh(i,cmd)
  if phase=='before':
   for source,dest in [(prefix+'_R_A1','10.2.1.10'),(prefix+'_R_B1','10.1.1.10')]:
    r=ex(source,'ping','-n','-c','3','-W','1',dest,check=False);records[-1].update(probe='actual-Linux-Outer-VM-nested-data',expected_result='delivered',observed_result='delivered'if r.returncode==0 else'no_reply')
except Exception as e:error=str(e)
finally:
 for i in [0,1]:
  try:ssh(i,'tail -n 150 /var/log/tdn-outer-charon.log',False)
  except Exception:pass
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'configuration':config,'initial_public_identities':initial if 'initial'in locals()else{},'records':records,'error':error,'runtime_backend':'Native FRR/OVS with actual FreeBSD Inner and Debian Linux Outer kernels','scope':['Only the fresh replay NC Outers are replaced. Native FRR and OVS neighboring devices retain their assigned MAC and interface identities. Original ND and other deployments are preserved.','The two actual Linux kernels permit independent Gray clock experiments without changing the host clock. Clock correction is a separate next collection.','Private credentials move only within the authorized worker and owned guests; public exports contain no credential bytes. Hardware remains shared and product approval is not claimed.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'probes':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
