import argparse,hashlib,json,socket,struct,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--mode',choices=['send','receive'],required=True);p.add_argument('--interface',required=True);p.add_argument('--source',required=True);p.add_argument('--destination',required=True);p.add_argument('--tags',type=int,required=True);p.add_argument('--token',required=True);p.add_argument('--output');a=p.parse_args();source=bytes.fromhex(a.source.replace(':',''));destination=bytes.fromhex(a.destination.replace(':',''));payload=('owned-public-opaque-Ethernet-'+a.token).encode().ljust(96,b'.');digest=hashlib.sha256(payload).hexdigest();tags=[]if a.tags==0 else([(0x8100,101)]if a.tags==1 else[(0x88a8,100),(0x8100,101)]);frame=destination+source+b''.join(struct.pack('!HH',proto,tci)for proto,tci in tags)+struct.pack('!H',0x88b5)+payload
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((a.interface,0));s.setsockopt(263,8,1);s.settimeout(.1)
if a.mode=='send':
 for i in range(4):s.send(frame);time.sleep(.04)
 print(json.dumps({'sent_frames':4,'source':a.source,'destination':a.destination,'tags':tags,'payload_sha256':digest,'frame_bytes':len(frame)}))
else:
 out=Path(a.output);out.with_suffix('.ready').write_text('ready');deadline=time.monotonic()+2;matches=[];other=0
 while time.monotonic()<deadline:
  try:data,anc,flags,address=s.recvmsg(65535,256)
  except socket.timeout:continue
  aux=False
  for level,kind,value in anc:
   if level==263 and kind==8 and len(value)>=20:
    status,length,snap,mac,net,tci,tpid=struct.unpack('=IIIHHHH',value[:20])
    if status&16:data=data[:12]+struct.pack('!HH',tpid if status&64 else 0x8100,tci)+data[12:];aux=True
  if data[:12]!=destination+source:continue
  offset=12;seen=[]
  while offset+4<=len(data)and int.from_bytes(data[offset:offset+2],'big')in [0x8100,0x88a8]:
   seen.append(struct.unpack('!HH',data[offset:offset+4]));offset+=4
  if offset+2>len(data)or data[offset:offset+2]!=bytes.fromhex('88b5'):continue
  actual=hashlib.sha256(data[offset+2:]).hexdigest()
  if actual==digest:matches.append({'at_ns':time.time_ns(),'tags':seen,'payload_sha256':actual,'payload_bytes':len(data)-offset-2,'frame_bytes':len(data),'aux_vlan_reconstructed':aux,'exact_expected_tags':seen==tags})
  else:other+=1
 result={'matches':matches,'other_payloads':other,'expected_tags':tags,'expected_payload_sha256':digest,'scope':'Synthetic public test payload; exact bytes are compared by digest. No real protected payload or ciphertext body is exported.'};out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'matches':len(matches),'all_tags_exact':all(r['exact_expected_tags']for r in matches)}))
s.close()
