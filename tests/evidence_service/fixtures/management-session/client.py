import socket,ssl,json,time,sys
c=ssl.create_default_context(cafile=sys.argv[1]);s=socket.socket();s.settimeout(5);s.bind(('10.31.0.1',41000));s.connect(('10.31.0.2',443))
with c.wrap_socket(s,server_hostname='outer.msc.test') as t:
 request=b'GET /status HTTP/1.1\r\nHost: outer.msc.test\r\n\r\n';t.sendall(request)
 print(json.dumps({'event':'request','peer':t.getpeername(),'local':t.getsockname(),'monotonic_ns':time.monotonic_ns(),'bytes_hex':request.hex()}),flush=True)
 response=t.recv(4096)
 print(json.dumps({'event':'response','monotonic_ns':time.monotonic_ns(),'bytes_hex':response.hex()}),flush=True)
 assert response.endswith(b'OK\n')
 time.sleep(3)
