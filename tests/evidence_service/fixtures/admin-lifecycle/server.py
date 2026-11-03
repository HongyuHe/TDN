import hashlib,json,socket,ssl,sys,time
from pathlib import Path
root,private=map(Path,sys.argv[1:])
accounts=json.loads((root/'accounts.json').read_text())
def event(kind,**fields):
 print(json.dumps({'kind':kind,'order':time.monotonic_ns(),**fields}),flush=True)
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.minimum_version=ssl.TLSVersion.TLSv1_3
c.load_cert_chain(str(private/'server.pem'),str(private/'server.key'));c.load_verify_locations(str(root/'ca.pem'));c.verify_mode=ssl.CERT_REQUIRED
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.32.0.2',8443));s.listen(8)
revoked=set();event('ready',address='10.32.0.2',port=8443)
for index in range(5):
 raw,remote=s.accept();local=raw.getsockname()
 try:
  channel=c.wrap_socket(raw,server_side=True)
 except ssl.SSLError as error:
  event('tlsRejected',remote=remote,local=local,error=str(error));raw.close();continue
 cert=hashlib.sha256(channel.getpeercert(binary_form=True)).hexdigest()
 binding=channel.get_channel_binding('tls-unique')
 if not binding:raise RuntimeError('TLS channel binding unavailable')
 session=hashlib.sha256(binding+repr((remote,local)).encode()+bytes.fromhex(cert)).hexdigest()
 account=next((a for a in accounts if a['certificateSha256']==cert),None)
 event('authenticationComplete',session=session,channelBindingSha256=hashlib.sha256(binding).hexdigest(),certificateSha256=cert,remote=remote,local=local,protocol=channel.version(),cipher=channel.cipher(),account=account['person'] if account else None,revoked=cert in revoked)
 request=channel.recv(4096);method,path,_=request.split(b'\r\n',1)[0].decode().split(' ')
 accepted=account is not None and cert not in revoked and (path=='/status' or (path=='/filter' and account['role']=='SecurityAdministrator'))
 status=200 if accepted else 403
 event('operation',session=session,certificateSha256=cert,person=account['person'] if account else None,method=method,path=path,status=status,requestHex=request.hex(),remote=remote,local=local)
 response=('HTTP/1.1 %d Result\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'%status).encode();channel.sendall(response)
 channel.close();event('connectionClosed',session=session,certificateSha256=cert)
 if index==2:
  revoked.add(cert);event('credentialRevoked',certificateSha256=cert,session=session,reason='configured lab revocation test')
s.close();event('stopped')
