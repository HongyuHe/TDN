import argparse,hashlib,json,re
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--names',nargs='+',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/protocol-publication-v5';out.mkdir();records=[]
def clean(s):
 s=re.sub(r'(?m)^([^\n]*hexdump[^\n]*:)[^\n]*$',r'\1 [REDACTED_HEXDUMP]',s);lines=[];continuation=False
 for line in s.splitlines(keepends=True):
  if continuation and re.match(r'^\s+(?:[0-9a-fA-F]{2}\s+){4,}',line):lines.append('     [REDACTED_HEXDUMP_CONTINUATION]\n');continue
  continuation='hexdump'in line and'[REDACTED_HEXDUMP]'in line;lines.append(line)
 return ''.join(lines)
def transform(v):
 if isinstance(v,str):return clean(v)
 if isinstance(v,list):return[transform(x)for x in v]
 if isinstance(v,dict):return{k:transform(x)for k,x in v.items()}
 return v
def strings(v):
 if isinstance(v,str):yield v
 elif isinstance(v,list):
  for x in v:yield from strings(x)
 elif isinstance(v,dict):
  for x in v.values():yield from strings(x)
for name in a.names:
 assert re.fullmatch('eap-tls-(forward|reverse)-v[0-9]+',name)
 target=root/'exports'/name;private=root/'private'/name;count=0
 for f in private.glob('*.log'):f.write_text(clean(f.read_text()));count+=1
 before=hashlib.sha256((target/'manifest.json').read_bytes()).hexdigest()
 for f in target.glob('*.json'):
  if f.name=='manifest.json':continue
  o=transform(json.loads(f.read_text()))
  for s in strings(o):
   assert not re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',s)
   assert not re.search(r'(?m)^[^\n]*hexdump(?:_ascii)?\(len=\d+\):[ \t]*[0-9a-fA-F]{2}(?:[ \t]|$)',s)
  f.write_text(json.dumps(o,indent=2)+'\n')
 m=json.loads((target/'manifest.json').read_text())
 for f in m['files']:
  path=target/f['path'];f['sha256']=hashlib.sha256(path.read_bytes()).hexdigest();f['bytes']=path.stat().st_size
 m['publication']={'sanitizer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'debug_hexdumps':'redacted in public exports and private debug logs','private_credential_files':'remain remote-only; never exported','decoded_scan':'passed'}
 (target/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
 records.append({'name':name,'before_manifest_sha256':before,'public_manifest_sha256':hashlib.sha256((target/'manifest.json').read_bytes()).hexdigest(),'private_debug_logs_redacted':count,'decoded_scan':'passed'})
(out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'scope':'Publication redacts diagnostic hexdumps and verifies decoded public JSON. Private credential files remain private. Exact source and final per-attempt manifests remain bound separately.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'bundles':len(records),'scan':'passed'}))
