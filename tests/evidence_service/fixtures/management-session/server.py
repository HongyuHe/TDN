import socket,ssl,json,time,sys
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(sys.argv[1],sys.argv[2])
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.31.0.2',443));s.listen(1)
print(json.dumps({'ready':True}),flush=True)
r,a=s.accept()
with c.wrap_socket(r,server_side=True) as t:
 request=t.recv(4096)
 print(json.dumps({'event':'request','peer':a,'local':t.getsockname(),'monotonic_ns':time.monotonic_ns(),'bytes_hex':request.hex()}),flush=True)
 response=b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n';t.sendall(response)
 print(json.dumps({'event':'response','monotonic_ns':time.monotonic_ns(),'bytes_hex':response.hex()}),flush=True)
 time.sleep(4)
