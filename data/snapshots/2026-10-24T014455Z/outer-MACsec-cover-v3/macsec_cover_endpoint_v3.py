import argparse,collections,fcntl,json,os,select,signal,socket,struct,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--interface',default='macsec0');p.add_argument('--peer',required=True);p.add_argument('--ready',required=True);p.add_argument('--output',required=True);p.add_argument('--interval-ms',type=int,default=20);p.add_argument('--frame-body-bytes',type=int,default=512);p.add_argument('--queue-limit',type=int,default=64);a=p.parse_args();running=True

def stop(sig,frame):
 global running
 running=False
signal.signal(signal.SIGTERM,stop)
fd=os.open('/dev/net/tun',os.O_RDWR|os.O_NONBLOCK);fcntl.ioctl(fd,0x400454ca,struct.pack('16sH',b'tfc0',0x1001))
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x88b5));s.bind((a.interface,0));s.setblocking(False)
source=bytes.fromhex(Path('/sys/class/net/'+a.interface+'/address').read_text().strip().replace(':',''));peer=bytes.fromhex(a.peer.replace(':',''));ether=peer+source+struct.pack('!H',0x88b5);queue=collections.deque();interval=a.interval_ms/1000;next_send=time.monotonic()+.1;max_payload=a.frame_body_bytes-24;seq=0;events=[];stats={'tun_received':0,'tun_delivered':0,'data_frames_sent':0,'dummy_frames_sent':0,'oversize_drops':0,'queue_full_drops':0,'invalid_records':0,'max_queue_depth':0,'send_errors':0};started=time.time_ns()
Path(a.ready).write_text(json.dumps({'ready_at_ns':started,'interface':a.interface,'tun':'tfc0','interval_ms':a.interval_ms,'frame_body_bytes':a.frame_body_bytes,'max_payload_bytes':max_payload,'queue_limit':a.queue_limit,'queue_policy':'FIFO; new oversized or full-queue packets are dropped; every scheduled slot still emits a fixed-length dummy or one data record.'})+'\n')
try:
 while running:
  readable,_,_=select.select([fd,s],[],[],max(0,min(.2,next_send-time.monotonic())))
  if fd in readable:
   try:data=os.read(fd,65535)
   except BlockingIOError:data=b''
   if data:
    stats['tun_received']+=1
    if len(data)>max_payload:stats['oversize_drops']+=1
    elif len(queue)>=a.queue_limit:stats['queue_full_drops']+=1
    else:queue.append(data);stats['max_queue_depth']=max(stats['max_queue_depth'],len(queue))
  if s in readable:
   try:data,addr=s.recvfrom(65535)
   except BlockingIOError:data=b'';addr=('',0,4)
   if data and addr[2]!=4:
    body=data[14:]
    if len(body)!=a.frame_body_bytes or body[:8]!=b'TDNFLOW1':stats['invalid_records']+=1
    else:
     length=int.from_bytes(body[16:18],'big')
     if length>max_payload:stats['invalid_records']+=1
     elif length:
      os.write(fd,body[24:24+length]);stats['tun_delivered']+=1
  now=time.monotonic()
  if now>=next_send:
   payload=queue.popleft()if queue else b'';seq+=1;body=b'TDNFLOW1'+struct.pack('!QH',seq,len(payload))+b'\0'*6+payload;body+=b'\0'*(a.frame_body_bytes-len(body));lag=(now-next_send)*1e9
   try:s.send(ether+body);stats['data_frames_sent'if payload else'dummy_frames_sent']+=1
   except OSError:stats['send_errors']+=1
   events.append({'sequence':seq,'at_ns':time.time_ns(),'schedule_lag_ns':int(lag),'kind':'data'if payload else'dummy','body_length':len(body),'queue_after_send':len(queue)})
   next_send+=interval
   if next_send<time.monotonic():next_send=time.monotonic()+interval
finally:
 s.close();os.close(fd);Path(a.output).write_text(json.dumps({'started_at_ns':started,'ended_at_ns':time.time_ns(),'settings':vars(a),'stats':stats,'send_events':events,'scope':'Laboratory size/rate masking shim before the actual MACsec controlled port. Configured slots are measured software events, not hard real-time guarantees. Receiver recovers records and discards dummy/padding. No RFC9347/IEEE privacy conformance or complete TRANSEC protection is asserted.'},indent=2)+'\n');print(json.dumps(stats))
