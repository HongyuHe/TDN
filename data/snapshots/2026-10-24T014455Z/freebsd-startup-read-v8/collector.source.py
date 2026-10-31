import argparse,hashlib,json,select,socket,time
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--label',required=True);p.add_argument('--socket',required=True);p.add_argument('--commands',nargs='+',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports'/a.label;out.mkdir();s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(a.socket);records=[];error=None
def exchange(text,seconds=2):
    s.sendall(text.encode());end=time.monotonic()+seconds;parts=[]
    while time.monotonic()<end:
        if not select.select([s],[],[],.2)[0]:continue
        block=s.recv(65536)
        if not block:break
        parts.append(block)
    value=b''.join(parts).decode(errors='replace');assert '-----BEGIN PRIVATE KEY-----'not in value;records.append({'at':datetime.now(timezone.utc).isoformat(),'sent':text,'received':value});return value
try:
    value=exchange('\n',1)
    if 'login:'in value:value=exchange('root\n',3)
    if 'Password:'in value:raise RuntimeError('Console authentication required; no password guessed or changed.')
    for cmd in a.commands:exchange(cmd+'\n',3)
except Exception as e:error=str(e)
finally:
    s.close();(out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'records':records,'error':error,'scope':'Only the owned replay VM console is controlled. Host/hypervisor administration is an explicit trusted laboratory control. Commands and exact responses are preserved.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'records':records}))
