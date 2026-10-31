import argparse,base64,hashlib,http.server,json,os,ssl,threading
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--bind',default='0.0.0.0');p.add_argument('--port',type=int,default=43463);p.add_argument('--root',required=True);p.add_argument('--ca',required=True);p.add_argument('--cert',required=True);p.add_argument('--key',required=True);p.add_argument('--max-bytes',type=int,default=8388608);a=p.parse_args();root=Path(a.root);root.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(root,0o700);journal=root/'audit-journal.jsonl';lock=threading.Lock();transactions={};offsets={}
if journal.exists():
 for line in journal.read_text().splitlines():
  r=json.loads(line);transactions[(r['device'],r['offset'])]=r;offsets[r['device']]=r['next']
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def answer(self,status,body):
  b=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def do_POST(self):
  if self.path!='/v1/audit':self.answer(404,{'error':'unknown endpoint'});return
  certificate=self.connection.getpeercert();cn=next((value for names in certificate.get('subject',[])for key,value in names if key=='commonName'),'')
  try:
   length=int(self.headers.get('Content-Length','0'));assert 0<length<=131072
   r=json.loads(self.rfile.read(length));data=base64.b64decode(r['data'],validate=True);assert len(data)<=65536 and hashlib.sha256(data).hexdigest()==r['sha256'];device=r['device'];offset=r['offset'];assert isinstance(offset,int)and offset>=0
  except Exception:self.answer(400,{'error':'invalid record'});return
  if cn!='NC-I-A'or device!=cn:self.answer(403,{'error':'certificate/device binding denied'});return
  with lock:
   old=transactions.get((device,offset))
   if old:
    if old['sha256']!=r['sha256']or old['bytes']!=len(data):self.answer(409,{'error':'different record at committed offset'});return
    self.answer(200,{'next':old['next'],'sha256':old['sha256'],'duplicate':True});return
   if offset!=offsets.get(device,0):self.answer(409,{'error':'noncontiguous offset'});return
   record={'device':device,'offset':offset,'next':offset+len(data),'bytes':len(data),'sha256':r['sha256'],'data':r['data'],'peer_cn':cn,'tls_version':self.connection.version(),'tls_cipher':self.connection.cipher()[0]};encoded=(json.dumps(record)+'\n').encode()
   if journal.exists()and journal.stat().st_size+len(encoded)>a.max_bytes or len(encoded)>a.max_bytes:self.answer(507,{'error':'configured durable-store budget reached'});return
   with journal.open('ab')as f:os.chmod(journal,0o600);f.write(encoded);f.flush();os.fsync(f.fileno())
   directory=os.open(root,os.O_RDONLY);os.fsync(directory);os.close(directory);transactions[(device,offset)]=record;offsets[device]=record['next'];self.answer(200,{'next':record['next'],'sha256':record['sha256'],'duplicate':False})
server=http.server.ThreadingHTTPServer((a.bind,a.port),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3;context.maximum_version=ssl.TLSVersion.TLSv1_3;context.verify_mode=ssl.CERT_REQUIRED;context.load_verify_locations(a.ca);context.load_cert_chain(a.cert,a.key);server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()
