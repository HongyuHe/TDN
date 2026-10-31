import argparse,hashlib,json,re
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);records=[]
def walk(v):
 if isinstance(v,str):return re.sub(r'(?m)^\s*0x[0-9a-f]+:.*(?:\n|$)','[REMOVED_TCPDUMP_UNDECODED_BODY]\n',v)
 if isinstance(v,list):return[walk(x)for x in v]
 if isinstance(v,dict):return{k:walk(x)for k,x in v.items()}
 return v
for directory in sorted(root.iterdir()):
 if not directory.is_dir():continue
 m=directory/'manifest.json'
 if not m.exists():continue
 previous=hashlib.sha256(m.read_bytes()).hexdigest();count=0
 for file in directory.glob('*.json'):
  if file.name=='manifest.json':continue
  obj=json.loads(file.read_text());transformed=walk(obj)
  count+=json.dumps(transformed).count('[REMOVED_TCPDUMP_UNDECODED_BODY]')
  file.write_text(json.dumps(transformed,indent=2)+'\n')
 obj=json.loads(m.read_text());obj['publication']={'sanitizer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'reason':'The installed tcpdump defaults to dumping unrecognized MACsec bodies. Undecoded hex lines are removed. Explicit field-only parser observations are collected separately.','removed_body_lines':count,'before_manifest_sha256':previous}
 (directory/'publication.source.py').write_bytes(Path(__file__).read_bytes())
 obj['files']=[{'path':f.name,'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in sorted(directory.iterdir())if f.is_file()and f.name!='manifest.json']
 m.write_text(json.dumps(obj,indent=2)+'\n');records.append({'bundle':directory.name,'removed_body_lines':count,'manifest_sha256':hashlib.sha256(m.read_bytes()).hexdigest()})
(root/'publication-v5.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},indent=2)+'\n');print(json.dumps({'bundles':len(records),'removed_body_lines':sum(r['removed_body_lines']for r in records)}))
