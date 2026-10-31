import socket,json;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.93.0.2',5514));out=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
while True:
 data,addr=s.recvfrom(4096)
 try:
  event=json.loads(data);ok=set(event)=={'device','severity','event'} and event['severity'] in ['warning','critical'] and len(event['event'])<200
 except Exception:ok=False
 print(json.dumps({'accepted':ok,'source':addr}),flush=True)
 if ok:out.sendto(json.dumps(event).encode(),('10.94.0.2',5514))
