import socket,json;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.94.0.2',5514))
while True:
 data,addr=s.recvfrom(4096);print(json.dumps({'source':addr,'event':json.loads(data)}),flush=True)
