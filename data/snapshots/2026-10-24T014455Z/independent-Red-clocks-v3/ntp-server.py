import socket,struct,time,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],123))
def stamp(t):
 x=t+2208988800
 return struct.pack("!II",int(x),int((x%1)*2**32))
while True:
 data,addr=s.recvfrom(1024)
 if len(data)<48:continue
 received=time.time();r=bytearray(48);r[0]=36;r[1]=2;r[2]=4;r[3]=236;r[12:16]=b"LOCL";r[16:24]=stamp(received);r[24:32]=data[40:48];r[32:40]=stamp(received);r[40:48]=stamp(time.time());s.sendto(r,addr)
