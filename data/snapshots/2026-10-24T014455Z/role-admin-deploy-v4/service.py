import hashlib,http.server,json,ssl,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
from urllib.parse import urlsplit
directory=Path(sys.argv[1]);roles=json.loads((directory/'role-map.json').read_text())
permissions={'SecurityAdministrator':{'GET':['/state','/audit'],'POST':['/filter','/audit/rotate']},'Auditor':{'GET':['/state','/audit'],'POST':['/audit/rotate']}}
def state():
 return {'diagnostic_filter_rules':subprocess.check_output(['iptables','-S','EVA3_INPUT'],text=True).splitlines()}
def events():
 return [json.loads(line) for p in sorted(directory.glob('audit*.jsonl')) for line in p.read_text().splitlines()]
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def principal(self):
  der=self.connection.getpeercert(binary_form=True);fingerprint=hashlib.sha256(der).hexdigest() if der else ''
  return fingerprint,roles.get(fingerprint,'Unmapped')
 def reply(self,status,data):
  content=json.dumps(data,sort_keys=True).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(content)));self.end_headers()
  if self.command!='HEAD':self.wfile.write(content)
 def audit(self,status):
  fingerprint,role=self.principal();entry={'at':datetime.now(timezone.utc).isoformat(),'fingerprint':fingerprint,'role':role,'method':self.command,'path':urlsplit(self.path).path,'status':status}
  with (directory/'audit.jsonl').open('a') as f:f.write(json.dumps(entry,sort_keys=True)+'\n')
 def handle_operation(self):
  fingerprint,role=self.principal();path=urlsplit(self.path).path
  if path=='/private-key':self.audit(403);self.reply(403,{'error':'not-exported'});return
  if path not in permissions.get(role,{}).get(self.command,[]):self.audit(403);self.reply(403,{'error':'operation-not-authorized'});return
  if self.command=='GET' and path=='/state':data=state()
  elif self.command=='GET' and path=='/audit':data={'events':events()}
  elif self.command=='POST' and path=='/filter':
   try:
    length=int(self.headers.get('Content-Length','0'))
    if length<1 or length>512:raise ValueError()
    value=json.loads(self.rfile.read(length))
    if set(value)!= {'diagnostic_block'} or type(value['diagnostic_block']) is not bool:raise ValueError()
   except (ValueError,TypeError,json.JSONDecodeError):self.audit(400);self.reply(400,{'error':'invalid-request'});return
   subprocess.run(['iptables','-F','EVA3_INPUT'],check=True)
   if value['diagnostic_block']:subprocess.run(['iptables','-A','EVA3_INPUT','-s','192.0.2.253/32','-p','icmp','-j','DROP'],check=True)
   subprocess.run(['iptables','-A','EVA3_INPUT','-j','RETURN'],check=True);data=state()
  elif self.command=='POST' and path=='/audit/rotate':
   current=directory/'audit.jsonl';number=len(list(directory.glob('audit-*.jsonl')))+1
   if current.exists():current.rename(directory/('audit-%04d.jsonl'%number))
   data={'rotation':number,'retained_events':len(events())}
  else:self.audit(405);self.reply(405,{'error':'method-not-supported'});return
  self.audit(200);self.reply(200,data)
 def do_GET(self):self.handle_operation()
 def do_POST(self):self.handle_operation()
 def do_HEAD(self):self.audit(403);self.reply(403,{'error':'not-exported'})
server=http.server.HTTPServer(('172.28.96.2',8443),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.maximum_version=ssl.TLSVersion.TLSv1_2;context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384');context.load_cert_chain(str(directory/'managed.pem'),str(directory/'managed.key'));context.load_verify_locations(str(directory/'ca.pem'));context.verify_mode=ssl.CERT_REQUIRED;server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()
