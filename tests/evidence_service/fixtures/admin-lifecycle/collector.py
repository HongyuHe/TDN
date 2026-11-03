#!/usr/bin/env python3
"""Capture account bindings and authenticated TLS-channel administration in an isolated lab."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

SERVER = r'''import hashlib,json,socket,ssl,sys,time
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
'''
CLIENT = r'''import hashlib,json,socket,ssl,sys,time
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
'''


def collect(root):
    root.mkdir(parents=True, exist_ok=False)
    private = root.parent / (root.name + '-private')
    private.mkdir(mode=0o711, exist_ok=False)
    commands, processes = [], []
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    error = None
    def run(argv, namespace=None):
        command = (['ip','netns','exec',namespace] if namespace else []) + list(map(str,argv))
        begin = time.monotonic_ns()
        result = subprocess.run(command,capture_output=True,text=True,timeout=15)
        row = {'id':'admin-%04d'%len(commands),'command':command,'startOrder':begin,'endOrder':time.monotonic_ns(),'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
        commands.append(row)
        if result.returncode:raise RuntimeError(result.stderr)
        return row
    try:
        run(['openssl','version'])
        run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:secp384r1','-nodes','-keyout',private/'ca.key','-out',root/'ca.pem','-days','2','-subj','/CN=V31 administration lab CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
        accounts=[]
        users={}
        for login in ['v31admin','v31auditor']:
            creation=run(['useradd','-M','-U','-s','/usr/sbin/nologin',login])
            identity=run(['id',login]);uid=int(run(['id','-u',login])['stdout']);gid=int(run(['id','-g',login])['stdout'])
            users[login]={'uid':uid,'gid':gid,'createdOrder':creation['endOrder'],'creationObservation':creation['id'],'identityObservation':identity['id']}
        for name,person,role in [('server','outer-service','Service'),('admin','lab-security-administrator','SecurityAdministrator'),('auditor','lab-auditor','Auditor')]:
            run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:secp384r1','-nodes','-keyout',private/(name+'.key'),'-out',private/(name+'.csr'),'-subj','/CN='+person])
            ext=root/(name+'.ext');ext.write_text('subjectAltName=DNS:outer.msc.test\nextendedKeyUsage=serverAuth\n' if name=='server' else 'extendedKeyUsage=clientAuth\n')
            target=private/'server.pem' if name=='server' else root/(name+'.pem')
            issuance=run(['openssl','x509','-req','-in',private/(name+'.csr'),'-CA',root/'ca.pem','-CAkey',private/'ca.key','-CAserial',private/'serial','-CAcreateserial','-out',target,'-days','2','-sha384','-extfile',ext])
            import ssl
            public=target.read_text();der=ssl.PEM_cert_to_DER_cert(public)
            if name=='server':shutil.copy2(target,root/'server.pem')
            else:
                login='v31admin' if name=='admin' else 'v31auditor'
                account=users[login]
                run(['chown',str(account['uid'])+':'+str(account['gid']),private/(name+'.key')])
                run(['chmod','600',private/(name+'.key')])
                accounts.append({'login':login,'uid':account['uid'],'gid':account['gid'],'unixAccountCreatedOrder':account['createdOrder'],'unixAccountCreationObservation':account['creationObservation'],'unixIdentityObservation':account['identityObservation'],'person':person,'role':role,'component':'V31_ADMIN_OUTER','credentialName':name,'certificateSha256':hashlib.sha256(der).hexdigest(),'createdOrder':issuance['endOrder'],'creationObservation':issuance['id'],'workstationAccount':True,'groupAccount':False,'scope':'Configured experimental identity; no real human identity assurance is claimed.'})
        (root/'accounts.json').write_text(json.dumps(accounts,indent=2)+'\n')
        for ns in ['v31admin-aw','v31admin-outer']:
            run(['ip','netns','add',ns]);run(['ip','link','set','lo','up'],ns)
        run(['ip','link','add','adma','type','veth','peer','name','admo'])
        for ns,port,address in [('v31admin-aw','adma','10.32.0.1/30'),('v31admin-outer','admo','10.32.0.2/30')]:
            run(['ip','link','set',port,'netns',ns]);run(['ip','addr','add',address,'dev',port],ns);run(['ip','link','set',port,'up'],ns)
        for name,source in [('server.py',SERVER),('client.py',CLIENT)]: (root/name).write_text(source)
        log=(root/'server.jsonl').open('w')
        command=['ip','netns','exec','v31admin-outer',sys.executable,'-u',str(root/'server.py'),str(root),str(private)]
        process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT);processes.append((process,log))
        commands.append({'id':'admin-%04d'%len(commands),'kind':'spawn','command':command,'pid':process.pid,'startOrder':time.monotonic_ns()})
        for _ in range(100):
            if '"ready"' in (root/'server.jsonl').read_text():break
            time.sleep(.03)
        else:raise RuntimeError('Administration listener did not become ready')
        run(['ss','-lntp'],'v31admin-outer')
        for index,(name,path) in enumerate([('admin','/filter'),('auditor','/filter'),('auditor','/status'),('auditor','/status'),('none','/status')]):
            identity=users['v31admin' if name=='admin' else 'v31auditor']
            run(['setpriv','--reuid',str(identity['uid']),'--regid',str(identity['gid']),'--clear-groups',sys.executable,root/'client.py',root,private,name,path,str(41000+index)],'v31admin-aw')
        process.wait(timeout=5)
        if process.returncode:raise RuntimeError('Administration server failed')
        log.flush()
        events=[json.loads(line) for line in (root/'server.jsonl').read_text().splitlines()]
        operations=[event for event in events if event['kind']=='operation']
        if [event['status'] for event in operations] != [200,403,200,403]:raise RuntimeError('Administration operation outcomes differ')
        if len([event for event in events if event['kind']=='tlsRejected']) != 1:raise RuntimeError('Missing rejected unauthenticated connection')
    except Exception as exc:
        error=str(exc)
    finally:
        for process,log in processes:
            if process.poll() is None:process.terminate();process.wait(timeout=5)
            log.close()
        for ns in ['v31admin-aw','v31admin-outer']:
            subprocess.run(['ip','netns','del',ns],capture_output=True)
        shutil.rmtree(private)
        (root/'collector.py').write_text(Path(__file__).read_text())
        (root/'observations.json').write_text(json.dumps({'startedAt':started,'endedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'commands':commands,'error':error,'privateFilesRemaining':0},indent=2)+'\n')
        (root/'manifest.json').write_text(json.dumps({'files':[{'path':str(p.relative_to(root)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(root.rglob('*')) if p.is_file()]},indent=2)+'\n')
    if error:raise RuntimeError(error)
    print(json.dumps({'capture':str(root),'success':True}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);collect(parser.parse_args().output)
