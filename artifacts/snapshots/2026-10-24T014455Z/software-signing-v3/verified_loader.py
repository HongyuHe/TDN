import hashlib,json,os,subprocess,sys
public='/public'
r=subprocess.run(['openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',public+'/publisher.pub','-in',public+'/software-manifest.json','-sigfile',public+'/software-manifest.sig'],capture_output=True,text=True)
if r.returncode:print(json.dumps({'signature_verified':False,'executed':False}));sys.exit(20)
m=json.load(open(public+'/software-manifest.json'));fd=os.open('/payload/twinet-linux',os.O_RDONLY);h=hashlib.sha256()
while True:
 data=os.read(fd,1048576)
 if not data:break
 h.update(data)
if h.hexdigest()!=m['sha256']or os.fstat(fd).st_size!=m['bytes']:print(json.dumps({'signature_verified':True,'payload_hash_verified':False,'executed':False}));sys.exit(21)
print(json.dumps({'signature_verified':True,'payload_hash_verified':True,'executing_verified_fd':True}),flush=True)
os.lseek(fd,0,os.SEEK_SET);os.execve(fd,['twinet-linux','--help'],os.environ)
