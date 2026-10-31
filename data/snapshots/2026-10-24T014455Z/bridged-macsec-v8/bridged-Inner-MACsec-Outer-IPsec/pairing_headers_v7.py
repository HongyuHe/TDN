import argparse,json,signal,socket,struct,time
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args();rows=[];running=True;started=datetime.now(timezone.utc).isoformat();errors=0

def stop(sig,frame):
 global running
 running=False
signal.signal(signal.SIGTERM,stop)
signal.signal(signal.SIGINT,stop)
def ethernet(data,depth=0):
 if len(data)<14:return {'truncated_header':True}
 dst=':'.join('%02x'%x for x in data[:6]);src=':'.join('%02x'%x for x in data[6:12]);proto=int.from_bytes(data[12:14],'big');body=data[14:];v={'destination_mac':dst,'source_mac':src,'ethertype':'0x%04x'%proto,'frame_length':len(data)}
 tags=[]
 while proto in [0x8100,0x88a8]and len(tags)<2:
  if len(body)<4:v['truncated_vlan_header']=True;return v
  tci,following=struct.unpack('!HH',body[:4]);tags.append({'tpid':'0x%04x'%proto,'tci':tci,'vid':tci&4095,'pcp':tci>>13,'dei':bool(tci&4096)});proto=following;body=body[4:]
 if tags:v['vlan_tags']=tags;v['inner_ethertype']='0x%04x'%proto
 if proto in [0x8100,0x88a8]:v['unsupported_vlan_depth']=True;return v
 if proto==0x88e5 and len(body)>=6:
  tci=body[0];v['macsec']={'tci_an':tci,'association_number':tci&3,'sci_present':bool(tci&0x20),'encrypted':bool(tci&8),'changed_text':bool(tci&4),'short_length':body[1],'packet_number':int.from_bytes(body[2:6],'big')}
  if tci&0x20 and len(body)>=14:v['macsec']['sci']=body[6:14].hex()
 elif proto==0x0800 and len(body)>=20:
  ihl=(body[0]&15)*4;pr=body[9];total=int.from_bytes(body[2:4],'big');fragment=int.from_bytes(body[6:8],'big');v['ipv4']={'source':socket.inet_ntoa(body[12:16]),'destination':socket.inet_ntoa(body[16:20]),'protocol':pr,'ihl':ihl,'total_length':int.from_bytes(body[2:4],'big'),'identification':int.from_bytes(body[4:6],'big'),'fragment_field':int.from_bytes(body[6:8],'big'),'ttl':body[8]}
  if ihl<20 or ihl>len(body) or total<ihl or total>len(body):v['transport_parse']='invalid_or_truncated_IPv4_length';return v
  if fragment&8191:v['transport_parse']='noninitial_IPv4_fragment';return v
  b=body[ihl:total]
  if pr==50 and len(b)>=8:v['esp']={'spi':int.from_bytes(b[:4],'big'),'sequence':int.from_bytes(b[4:8],'big')}
  elif pr==17 and len(b)>=8:
   sp,dp,length,checksum=struct.unpack('!HHHH',b[:8]);v['udp']={'source_port':sp,'destination_port':dp,'length':length}
   if sp==1701 and dp==1701 and len(b)>=20:
    u=b[8:];flags=int.from_bytes(u[:2],'big');v['l2tpv3']={'flags_version':flags,'version':flags&15,'reserved':int.from_bytes(u[2:4],'big'),'session_id':int.from_bytes(u[4:8],'big'),'default_l2specific_sublayer':int.from_bytes(u[8:12],'big')}
    if flags&15==3 and not flags&0x8000 and depth<2 and len(u)>=26:v['encapsulated_ethernet']=ethernet(u[12:],depth+1)
  elif pr==1 and len(b)>=2:v['icmp']={'type':b[0],'code':b[1]}
 elif proto==0x86dd and len(body)>=40:v['ipv6']={'source':socket.inet_ntop(socket.AF_INET6,body[8:24]),'destination':socket.inet_ntop(socket.AF_INET6,body[24:40]),'immediate_next_header':body[6],'payload_length':int.from_bytes(body[4:6],'big'),'hop_limit':body[7]}
 return v
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.setsockopt(263,8,1);s.settimeout(.2)
try:
 while running:
  try:
   data,anc,flags,addr=s.recvmsg(65535,256)
   for level,kind,value in anc:
    if level==263 and kind==8 and len(value)>=20:
     status,length,snap,mac,net,tci,tpid=struct.unpack('=IIIHHHH',value[:20])
     if status&16:data=data[:12]+struct.pack('!HH',tpid if status&64 else 0x8100,tci)+data[12:]
  except socket.timeout:continue
  try:
   if len(rows)<10000:rows.append({'at_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns(),'interface':addr[0],'packet_type':addr[2],'headers':ethernet(data)})
   else:errors+=1
  except (ValueError,IndexError,struct.error):errors+=1
finally:
 s.close();o={'started_at':started,'ended_at':datetime.now(timezone.utc).isoformat(),'frames':rows,'parse_or_capacity_errors':errors,'scope':'Only parsed public Ethernet, IPv4/IPv6, UDP, ICMP, ESP SPI/sequence, MACsec SecTAG and L2TPv3 data headers are emitted. Packet payload and ciphertext bytes are never serialized. MACsec encrypted content is never parsed. IPv4 transport headers require a valid complete IHL/total length and zero fragment offset. The selected L2TPv3 contract is UDP, no cookie and a four-byte default L2-specific sublayer, corroborated by actual tunnel/session state. Up to two802.1Q/802.1ad VLAN tags are parsed, including reconstruction from Linux PACKET_AUXDATA when supplied. Deeper tags and other L2TP cookie/sublayer arrangements remain unsupported. Opaque EtherType payload bytes remain unparsed.'};Path(a.output).write_text(json.dumps(o,indent=2)+'\n');print(json.dumps({'frames':len(rows),'parse_or_capacity_errors':errors}))
