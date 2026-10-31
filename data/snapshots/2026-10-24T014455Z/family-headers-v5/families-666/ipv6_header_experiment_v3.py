import hashlib,json,socket,subprocess,time
from pathlib import Path
def exercise(lab):
 lab.code_hashes['ipv6_header_experiment_v3.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
 for cmd in [['uname','-a'],['ip6tables','--version'],['ip6tables-save'],['modinfo','ip6_tables'],['modinfo','nf_tables']]:lab.run(cmd,'OA',False)
 server="import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.bind(('fd30:1::1',9999));s.settimeout(25)\nwhile True:\n try:d,a=s.recvfrom(4096);s.sendto(d,a);print('echo',len(d),a,flush=True)\n except TimeoutError:break"
 process=subprocess.Popen(['ip','netns','exec',lab.prefix+'OA','python3','-u','-c',server],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  lab.run(['ip6tables','-I','INPUT','1','-i','black','-p','udp','--dport','9999','-j','ACCEPT'],'OA')
  lab.run(['ip6tables','-A','INPUT','-i','black','-p','udp','-j','DROP'],'OA')
  time.sleep(.2)
  local=json.loads(lab.run(['ip','-j','link','show','inside'],'FA').stdout)[0]['address']
  peer=json.loads(lab.run(['ip','-j','link','show','black'],'OA').stdout)[0]['address']
  client=r"""import socket,struct,json,sys
ext=int(sys.argv[1]);src='fd30:1::2';dst='fd30:1::1';payload=b'ipv6-field-probe'
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.bind((src,9998));s.settimeout(1)
a=socket.inet_pton(socket.AF_INET6,src);b=socket.inet_pton(socket.AF_INET6,dst);ulen=8+len(payload)
u=struct.pack('!HHHH',9998,9999,ulen,0)+payload
pseudo=a+b+struct.pack('!I3xB',ulen,17)+u
if len(pseudo)%2:pseudo+=b'\0'
v=sum(struct.unpack('!%dH'%(len(pseudo)//2),pseudo));v=(v&65535)+(v>>16);v=(v&65535)+(v>>16);ck=(~v)&65535 or 65535
u=struct.pack('!HHHH',9998,9999,ulen,ck)+payload
e=bytes([17,0,1,4,0,0,0,0])if ext else b''
hdr=struct.pack('!IHBB',6<<28,len(e+u),60 if ext else 17,64)+a+b
mac=lambda x:bytes.fromhex(x.replace(':',''))
frame=mac(sys.argv[3])+mac(sys.argv[2])+b'\x86\xdd'+hdr+e+u
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);raw.bind(('inside',0));raw.send(frame)
received=False
try:d,addr=s.recvfrom(4096);received=d==payload
except TimeoutError:pass
print(json.dumps({'immediate_next_header':60 if ext else 17,'upper_protocol':17,'extension_header_bytes':len(e),'udp_checksum':ck,'frame_sha256':__import__('hashlib').sha256(frame).hexdigest(),'echo_received':received}))
sys.exit(0 if received else 1)
"""
  def probe(extension,expect,label):
   r=lab.run(['python3','-c',client,str(int(extension)),local,peer],'FA',False)
   lab.probes.append({'id':label,'source_device':'FA','destination':'fd30:1::1 UDP9999','expected_result':expect,'observed_result':'delivered'if r.returncode==0 else 'no_reply'if r.returncode==1 else 'collection_error','observation_id':lab.commands[-1]['id']})
  probe(False,'delivered','plain-UDP-before-immediate-filter')
  probe(True,'delivered','destination-options-accepted-by-protocol-match')
  lab.run(['ip6tables-save','-c'],'OA')
  lab.run(['ip6tables','-t','raw','-N','EVA6_NEXT'],'OA')
  for value in [6,17,50,58]:
   lab.run(['ip6tables','-t','raw','-A','EVA6_NEXT','-m','u32','--u32','4>>8&0xFF='+str(value),'-j','RETURN'],'OA')
  lab.run(['ip6tables','-t','raw','-A','EVA6_NEXT','-j','DROP'],'OA')
  lab.run(['ip6tables','-t','raw','-I','PREROUTING','1','-i','black','-j','EVA6_NEXT'],'OA')
  probe(True,'no_reply','destination-options-rejected-by-immediate-field')
  probe(False,'delivered','plain-UDP-after-immediate-filter')
  lab.run(['ip6tables-save','-c'],'OA')
  lab.ping('HA','fd10:2::2','delivered','protected-traffic-after-header-filter')
  for node,iface,mtu in [('HA','red',1280),('HB','red',1280),('IA','red',1280),('IB','red',1280),('IA','gray',1400),('IB','gray',1400),('OA','gray',1400),('OB','gray',1400)]:
   lab.run(['ip','link','set',iface,'mtu',mtu],node)
  r=lab.run(['ping','-6','-n','-c','3','-W','1','-M','do','-s','1232','fd10:2::2'],'HA',False)
  lab.probes.append({'id':'IPv6-Red1280-nested-protected','source_device':'HA','destination':'fd10:2::2','expected_result':'delivered','observed_result':'delivered'if r.returncode==0 else 'no_reply','observation_id':lab.commands[-1]['id']})
  lab.run(['ping','-6','-n','-c','1','-W','1','-M','do','-s','1300','fd10:2::2'],'HA',False)
  lab.state('header-and-MTU-after')
 finally:
  process.terminate()
  try:stdout,stderr=process.communicate(timeout=2)
  except subprocess.TimeoutExpired:process.kill();stdout,stderr=process.communicate()
  (lab.root/'udp-service-public.json').write_text(json.dumps({'command':process.args,'stdout':stdout,'stderr':stderr,'scope':'Diagnostic UDP echo only, using legitimate adjacent Black link addresses. No claim that the diagnostic service is a production MSC permitted service.'},indent=2)+'\n')
