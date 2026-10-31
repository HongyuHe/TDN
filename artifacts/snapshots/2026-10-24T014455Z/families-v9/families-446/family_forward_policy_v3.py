import hashlib,json,socket,subprocess,time
from pathlib import Path
def repair(lab,red,gray,black):
 lab.code_hashes['family_forward_policy_v3.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
 (lab.root/'family_forward_policy_v3.py').write_bytes(Path(__file__).read_bytes())
 tests=[]
 if red!=gray:tests.append(('Inner','HA','red','IA','red','gray','10.11.0.2'if gray==4 else'fd20:1::2'))
 if gray!=black:tests.append(('Outer','IA','gray','OA','gray','black','192.0.2.2'if black==4 else'fd30:1::2'))
 listener=r"""import socket,struct,json,sys,time,hashlib
iface,dst=sys.argv[1:];s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((iface,0));s.settimeout(.2);end=time.monotonic()+2.5;seen=[]
while time.monotonic()<end:
 try:frame,meta=s.recvfrom(65535)
 except TimeoutError:continue
 if len(frame)<54:continue
 data=frame[14:];v=data[0]>>4
 if v==4:
  h=(data[0]&15)*4
  if data[9]!=17 or socket.inet_ntoa(data[16:20])!=dst:continue
  src=socket.inet_ntoa(data[12:16])
 elif v==6:
  h=40
  if data[6]!=17 or socket.inet_ntop(socket.AF_INET6,data[24:40])!=dst:continue
  src=socket.inet_ntop(socket.AF_INET6,data[8:24])
 else:continue
 if len(data)<h+8 or struct.unpack('!H',data[h+2:h+4])[0]!=41002:continue
 seen.append({'family':v,'source':src,'destination':dst,'protocol':17,'packet_type':meta[2],'frame_sha256':hashlib.sha256(frame).hexdigest()})
print(json.dumps({'egress_captured':bool(seen),'headers':seen}))
"""
 sender=r"""import socket,struct,sys,hashlib,json,time
iface,smac,dmac,dst=sys.argv[1:];v=6 if ':'in dst else 4;payload=b'wrong-family-ingress-control';u=struct.pack('!HHHH',41001,41002,8+len(payload),0)+payload
if v==4:
 src='198.18.255.10';h=struct.pack('!BBHHHBBH4s4s',69,0,20+len(u),1234,0,64,17,0,socket.inet_aton(src),socket.inet_aton(dst));words=struct.unpack('!10H',h);x=sum(words);x=(x&65535)+(x>>16);x=(x&65535)+(x>>16);h=h[:10]+struct.pack('!H',(~x)&65535)+h[12:];etype=b'\x08\x00'
else:
 src='fd99::99';a=socket.inet_pton(socket.AF_INET6,src);b=socket.inet_pton(socket.AF_INET6,dst);pseudo=a+b+struct.pack('!I3xB',len(u),17)+u
 if len(pseudo)%2:pseudo+=b'\0'
 x=sum(struct.unpack('!%dH'%(len(pseudo)//2),pseudo));x=(x&65535)+(x>>16);x=(x&65535)+(x>>16);ck=(~x)&65535 or 65535;u=u[:6]+struct.pack('!H',ck)+u[8:];h=struct.pack('!IHBB',6<<28,len(u),17,64)+a+b;etype=b'\x86\xdd'
frame=bytes.fromhex(dmac.replace(':',''))+bytes.fromhex(smac.replace(':',''))+etype+h+u;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind((iface,0))
for i in range(3):s.send(frame);time.sleep(.1)
print(json.dumps({'injected_family':v,'claimed_source':src,'destination':dst,'udp_destination':41002,'frame_sha256':hashlib.sha256(frame).hexdigest(),'count':3,'scope':'Raw Ethernet injection from actual ingress namespace; source address is intentionally not assumed to be an assigned Red address.'}))
"""
 def crafted(test,phase):
  role,source,siface,gateway,ingress,egress,dst=test
  smac=json.loads(lab.run(['ip','-j','link','show',siface],source).stdout)[0]['address'];dmac=json.loads(lab.run(['ip','-j','link','show',ingress],gateway).stdout)[0]['address']
  args=['ip','netns','exec',lab.prefix+gateway,'python3','-c',listener,egress,dst];process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);time.sleep(.2)
  lab.run(['python3','-c',sender,siface,smac,dmac,dst],source)
  stdout,stderr=process.communicate(timeout=4);observation=json.loads(stdout);record={'id':'wrong-family-'+role+'-'+phase,'command':args,'returncode':process.returncode,'stdout':stdout,'stderr':stderr,'scope':'Packet header capture on the gateway egress interface. No payload or secret key bytes are retained.'};lab.commands.append(record)
  lab.probes.append({'id':record['id'],'source_device':source,'destination':dst,'expected_result':'forwarded'if phase=='before'else'blocked','observed_result':'forwarded'if observation['egress_captured']else'blocked','observation_id':record['id']})
 for test in tests:crafted(test,'before')
 lab.state('before-dual-family-forward-repair')
 for node in ['IA','IB','OA','OB']:
  for tool in ['iptables','ip6tables']:lab.run([tool,'-P','FORWARD','DROP'],node);lab.run([tool+'-save','-c'],node)
 for test in tests:crafted(test,'after')
 (lab.root/'dual-family-forward-policy.json').write_text(json.dumps({'request_id':'C-FAMILY-FILTER-002','devices':['IA','IB','OA','OB'],'families':[4,6],'forward_default':'DROP','permits':'Existing interface- and reqid-bound --pol ipsec permits remain explicit for the required payload family. No second-family cleartext forwarding permit is added.','crafted_tests':tests,'scope':'Before and after raw wrong-family ingress uses arbitrary claimed sources and captures actual plaintext UDP egress. Same-family all-packet claims still require the complete route/filter/XFRM model.'},indent=2)+'\n')
