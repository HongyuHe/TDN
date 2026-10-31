import argparse,hashlib,json,subprocess,time
from pathlib import Path
from pairing_execution_v6 import Lab,utc
p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args();lab=Lab(a.output,'outer-MACsec-cover-v4');lab.prefix='tcv3tf4-';processes=[];windows=[];error=None
for name in ['macsec_cover_lab_v4.py','macsec_cover_endpoint_v4.py']:
 f=Path(__file__).with_name(name);lab.code_hashes[name]=hashlib.sha256(f.read_bytes()).hexdigest();(lab.root/name).write_bytes(f.read_bytes())
def window(label,action):
 begin=time.time_ns();action();windows.append({'label':label,'started_at_ns':begin,'ended_at_ns':time.time_ns()})
try:
 for n,r in [('HA','host'),('IA','inner'),('OA','outer'),('BF','outer-ethernet-firewall'),('OB','outer'),('IB','inner'),('HB','host')]:lab.node(n,r,n[-1])
 for n in ['OA','OB','BF']:lab.run(['sysctl','-qw','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1'],n)
 for h,i,subnet in [('HA','IA','10.1.0.'),('HB','IB','10.2.0.')]:lab.link(h,'red',i,'red',subnet+'2/24',subnet+'1/24','red')
 lab.route('HA','10.2.0.0/24','10.1.0.1');lab.route('HB','10.1.0.0/24','10.2.0.1')
 lab.link('IA','gray','OA','gray','10.11.0.1/30','10.11.0.2/30');lab.link('IB','gray','OB','gray','10.21.0.1/30','10.21.0.2/30')
 for node,red,gray,via in [('IA','10.2.0.0/24','10.21.0.1/32','10.11.0.2'),('IB','10.1.0.0/24','10.11.0.1/32','10.21.0.2')]:lab.route(node,red,via);lab.route(node,gray,via)
 lab.esp('IA','IB','10.11.0.1','10.21.0.1','10.1.0.0/24','10.2.0.0/24',100,'inner')
 lab.link('OA','black','BF','p1',zone='black');lab.link('OB','black','BF','p2',zone='black');lab.run(['ip','link','add','br0','type','bridge'],'BF')
 for port in ['p1','p2']:lab.run(['ip','link','set',port,'master','br0'],'BF')
 lab.run(['ip','link','set','br0','up'],'BF');lab.run(['ebtables','-P','FORWARD','DROP'],'BF');lab.run(['ebtables','-A','FORWARD','-p','0x88e5','-j','ACCEPT'],'BF')
 lab.macsec('OA','OB','black','black','10.90.0.1/30','10.90.0.2/30','outer')
 for n in ['OA','OB']:lab.run(['ip','addr','flush','dev','macsec0'],n)
 mac={n:json.loads(lab.run(['ip','-j','link','show','macsec0'],n).stdout)[0]['address']for n in ['OA','OB']}
 for node,peer in [('OA','OB'),('OB','OA')]:
  ready=lab.root/(node+'-ready.json');output=lab.root/(node+'-cover-events.json');cmd=['ip','netns','exec',lab.prefix+node,'python3',str(Path(__file__).with_name('macsec_cover_endpoint_v4.py')),'--peer',mac[peer],'--ready',str(ready),'--output',str(output)]
  proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append((node,cmd,proc,utc()))
 for node,peerip,address in [('OA','10.21.0.1/32','10.91.0.1/30'),('OB','10.11.0.1/32','10.91.0.2/30')]:
  deadline=time.monotonic()+10
  while not(lab.root/(node+'-ready.json')).exists():
   assert time.monotonic()<deadline,'TFC endpoint did not create its public ready record'
   time.sleep(.1)
  lab.run(['ip','addr','add',address,'dev','tfc0'],node);lab.run(['ip','link','set','tfc0','mtu','488','up'],node);lab.run(['ip','route','replace',peerip,'dev','tfc0'],node)
 for node in ['IA','IB','OA','OB']:
  for ipt in ['iptables','ip6tables']:lab.run([ipt,'-P','FORWARD','DROP'],node)
  if node in ['IA','IB']:
   for inside,outside,direction in [('red','gray','out'),('gray','red','in')]:lab.run(['iptables','-A','FORWARD','-i',inside,'-o',outside,'-m','policy','--dir',direction,'--pol','ipsec','--reqid','100','-j','ACCEPT'],node)
  else:
   for inside,outside in [('gray','tfc0'),('tfc0','gray')]:lab.run(['iptables','-A','FORWARD','-i',inside,'-o',outside,'-p','esp','-j','ACCEPT'],node)
 lab.start_headers();window('idle-before',lambda:time.sleep(3))
 def useful():
  lab.ping('HA','10.2.0.2','delivered','protected-A-B-through-cover-and-MACsec');lab.ping('HB','10.1.0.2','delivered','protected-B-A-through-cover-and-MACsec')
 window('useful-load',useful);window('idle-after',lambda:time.sleep(3));lab.state('stable-before')
 lab.run(['ip','xfrm','state','flush'],'IA');lab.ping('HA','10.2.0.2','no_reply','Inner-SA-loss-fails-closed');lab.restore_inner();lab.ping('HA','10.2.0.2','delivered','restored-protected-data')
 lab.run(['ip','link','set','macsec0','down'],'OA');lab.ping('HA','10.2.0.2','no_reply','Outer-MACsec-loss-fails-closed');lab.run(['ip','link','set','macsec0','up'],'OA');lab.ping('HA','10.2.0.2','delivered','Outer-MACsec-restored-data');lab.state('stable-after')
except Exception as exc:error=str(exc)
finally:
 for node,cmd,proc,started in processes:
  proc.terminate();stdout,stderr=proc.communicate(timeout=10);lab.commands.append({'id':'cmd-%04d'%len(lab.commands),'started_at':started,'ended_at':utc(),'command':cmd,'device_id':node,'returncode':proc.returncode,'stdout':stdout,'stderr':stderr})
 (lab.root/'windows.json').write_text(json.dumps({'windows':windows,'scope':'Bounded idle/useful/idle observation windows are clock measurements. The schedule is an implemented rule with observed jitter, not a hard real-time guarantee.'},indent=2)+'\n');lab.finish(error)
