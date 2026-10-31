import hashlib,json,shlex,socket,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-replay-20261024-v7');out=root/'exports/freebsd-native-integration-v3';out.mkdir();private=root/'private/freebsd-native-creds';private.mkdir(mode=0o700);records=[];started=datetime.now(timezone.utc).isoformat();error=None
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
 initial={}
 for d in spec['devices']:
  info=json.loads(run(['docker','inspect','--format','{{json .}}',d['id']]).stdout)
  if info['Config']['Labels'].get('twinet.msc.lab')!=spec['name']:raise RuntimeError('Foreign component refused')
  initial[d['id']]={'pid':info['State']['Pid'],'container_id':info['Id'],'interfaces':json.loads(ex(d['id'],'ip','-j','-d','address').stdout)}
 for i,site in enumerate(['A','B']):
  did='NQ_I_'+site+'1';directory=private/site;directory.mkdir(mode=0o700)
  run(['docker','cp',did+':/etc/swanctl',str(directory)])
  ssh(i,'mkdir -p /usr/local/etc/swanctl')
  run(['scp','-qr','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-i',str(root/'private/freebsd/management_key'),'-P',str(22392+i),str(directory/'swanctl'),'root@127.0.0.1:/usr/local/etc/'])
  run(['docker','stop','-t','3',did])
  for j,zone in enumerate(['red','gray']):
   index=2*i+j;peer='NQ_R_'+site+'1' if zone=='red' else 'NQ_G_'+site+'1';iface='red' if zone=='red' else 'inner';peerold=next(p for p in initial[peer]['interfaces'] if p['ifname']==iface);innerold=next(p for p in initial[did]['interfaces'] if p['ifname']==zone);pid=initial[peer]['pid']
   check=ex(peer,'ip','link','show',iface,check=False)
   if check.returncode==0:raise RuntimeError('Refuse replacing live native endpoint')
   bridge='nq3b'+str(index);tap='nq3t'+str(index);host='nq3h'+str(index);port='nq3p'+str(index)
   run(['ip','link','add',bridge,'type','bridge','stp_state','0']);run(['ip','link','set',bridge,'up'])
   run(['ip','tuntap','add','dev',tap,'mode','tap']);run(['ip','link','set',tap,'master',bridge]);run(['ip','link','set',tap,'up'])
   run(['ip','link','add',host,'type','veth','peer','name',port]);run(['ip','link','set',host,'master',bridge]);run(['ip','link','set',host,'up']);run(['ip','link','set',port,'netns',pid]);run(['nsenter','-t',pid,'-n','ip','link','set',port,'name',iface]);ex(peer,'ip','link','set',iface,'address',peerold['address'],'mtu',peerold['mtu'],'up')
   for addr in peerold.get('addr_info',[]):
    if addr['family']=='inet':ex(peer,'ip','address','replace',addr['local']+'/'+str(addr['prefixlen']),'dev',iface)
   device=next(d for d in spec['devices'] if d['id']==peer)
   for route in device.get('routes',[]):ex(peer,'ip','route','replace',route['prefix'],'via',route['via'])
   hmp(i,'netdev_add tap,id=nq3'+zone+',ifname='+tap+',script=no,downscript=no')
   hmp(i,'device_add virtio-net-pci,id=nq3'+zone+'nic,netdev=nq3'+zone+',mac='+innerold['address'])
  siteid=1 if site=='A' else 2;remoteid=2 if site=='A' else 1
  cmds=['kldstat -n ipsec >/dev/null 2>&1 || kldload ipsec','sysrc kld_list+=ipsec','sysctl kern.crypto.allow_soft=1','sysctl net.inet.ipsec.debug=0','sysctl net.inet.ip.forwarding=1','ifconfig vtnet1 down','ifconfig vtnet2 inet 10.'+str(siteid)+'.1.1/24 mtu 1320 up','ifconfig vtnet3 inet 10.'+str(siteid)+'00.1.2/24 mtu 1400 up','route delete default','route add -net 10.'+str(remoteid)+'.1.0/24 10.'+str(siteid)+'00.1.1','route add -host 10.'+str(remoteid)+'00.1.2 10.'+str(siteid)+'00.1.1']
  for cmd in cmds:ssh(i,cmd)
  config='charon {\n install_routes = no\n load_modular = yes\n plugins {\n include strongswan.d/charon/*.conf\n }\n}\ninclude strongswan.d/*.conf\n'
  ssh(i,'printf %s '+shlex.quote(config)+' > /usr/local/etc/strongswan.conf')
  ssh(i,'daemon -o /root/tdn-freebsd-v3/charon-runtime.log -p /root/tdn-freebsd-v3/charon.pid /usr/local/libexec/ipsec/charon </dev/null >/dev/null 2>&1')
  time.sleep(1);ssh(i,'/usr/local/sbin/swanctl --load-all')
  for cmd in ['uname -a','ifconfig -a','netstat -rn','/usr/local/sbin/swanctl --list-algs','/usr/local/sbin/swanctl --stats','ldd /usr/local/lib/ipsec/plugins/libstrongswan-botan.so','pkg info botan3','cat /usr/local/etc/swanctl/swanctl.conf']:ssh(i,cmd)
 ssh(0,'/usr/local/sbin/swanctl --initiate --child protected',timeout=90)
 for phase in ['before','after']:
  records.append({'id':'phase-'+phase,'command':['phase',phase],'returncode':0,'stdout':'','stderr':''})
  for i in [0,1]:
   for cmd in ['/usr/local/sbin/swanctl --list-sas','netstat -s -p esp','setkey -DP','netstat -rn']:ssh(i,cmd,check=False)
  for did in ['NQ_O_A1','NQ_O_B1']:ex(did,'swanctl','--list-sas');ex(did,'ip','-s','xfrm','state','list','nokeys')
  if phase=='before':
   for source,dest in [('NQ_R_A1','10.2.1.10'),('NQ_R_B1','10.1.1.10')]:
    r=ex(source,'ping','-n','-c','3','-W','1',dest,check=False);records[-1].update(probe='cross-OS-nested-data',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply' if r.returncode==1 else 'collection_error')
 for i in [0,1]:ssh(i,'cat /root/tdn-freebsd-v3/charon-runtime.log')
except Exception as e:error=str(e)
finally:
 data={'schema_version':'csfc-native-different-OS/v1','started_at':started,'ended_at':datetime.now(timezone.utc).isoformat(),'runtime_backend':'native-FRR-OVS-Linux-Outer-with-QEMU-FreeBSD-Inner','spec':spec,'records':records,'error':error,'scope':['Actual FreeBSD Inner kernels and Botan IKE cryptographic plugin replace only the two owned ND Inner containers. Native Linux Outers, FRR routing and OVS switching remain active.','Private test credential copying occurs entirely within pc22 and its guests; no private bytes enter these public artifacts.','Physical hardware remains shared in this case. Four-worker physical-role separation is a separate case.','Different OS and observed cryptographic implementation do not establish approved products, independent manufacturers/subsidiary relationships, or an NSA independence determination.','The guest management interface and virtualization host remain explicit trusted control infrastructure. No all-execution MAC confinement or non-bypass claim follows from finite traffic.']}
 (out/'observations.json').write_text(json.dumps(data,indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':'observations.json','sha256':hashlib.sha256((out/'observations.json').read_bytes()).hexdigest()}]},indent=2)+'\n')
 print(json.dumps({'error':error,'records':len(records),'probes':[r for r in records if 'probe' in r]}))
