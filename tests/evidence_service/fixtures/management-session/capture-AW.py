import socket,time,json,sys
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('gray',0))
print(json.dumps({'ready':True}),flush=True)
while True:
 b,a=s.recvfrom(65535)
 if len(b)>34 and b[12:14]==bytes.fromhex('0800') and b[23]==6:
  print(json.dumps({'monotonic_ns':time.monotonic_ns(),'interface':a[0],'packet_type':a[2],'frame_hex':b.hex()}),flush=True)
