import socket,struct,time;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.95.0.2',123))
while True:
 data,addr=s.recvfrom(1024);now=time.time()+2208988800;stamp=struct.pack('!II',int(now),int((now%1)*2**32));r=bytearray(48);r[0]=36;r[1]=2;r[24:32]=data[40:48];r[32:40]=stamp;r[40:48]=stamp;s.sendto(r,addr);print('time response',flush=True)
