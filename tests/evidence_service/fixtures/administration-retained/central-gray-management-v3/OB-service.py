import http.server,ssl,sys
s=http.server.HTTPServer(('0.0.0.0',8443),http.server.SimpleHTTPRequestHandler)
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.minimum_version=ssl.TLSVersion.TLSv1_2;c.load_cert_chain(sys.argv[1]+'/server.pem',sys.argv[1]+'/server.key');c.load_verify_locations(sys.argv[1]+'/ca.pem');c.verify_mode=ssl.CERT_REQUIRED
s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()
