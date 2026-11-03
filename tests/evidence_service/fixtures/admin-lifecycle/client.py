import hashlib,json,socket,ssl,sys,time
from pathlib import Path
root,private=map(Path,sys.argv[1:3]);name,path,port=sys.argv[3:]
c=ssl.create_default_context(cafile=str(root/'ca.pem'));c.minimum_version=ssl.TLSVersion.TLSv1_3
if name!='none':c.load_cert_chain(str(root/(name+'.pem')),str(private/(name+'.key')))
s=socket.socket();s.settimeout(3);s.bind(('10.32.0.1',int(port)));s.connect(('10.32.0.2',8443))
try:
 with c.wrap_socket(s,server_hostname='outer.msc.test') as t:
  request=('GET '+path+' HTTP/1.1\r\nHost: outer.msc.test\r\nConnection: close\r\n\r\n').encode();t.sendall(request)
  response=t.recv(4096)
  print(json.dumps({'event':'response','name':name,'local':t.getsockname(),'peer':t.getpeername(),'requestHex':request.hex(),'responseHex':response.hex(),'order':time.monotonic_ns()}))
except ssl.SSLError as error:print(json.dumps({'event':'tlsRejected','name':name,'error':str(error),'order':time.monotonic_ns()}))
