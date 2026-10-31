import hashlib,json,re
from pathlib import Path
from datetime import datetime,timezone
run=Path('artifacts/construction/2026-10-24T014455Z');base=Path('artifacts/snapshots/2026-10-24T014455Z');store=run/'evidence/source-store';store.mkdir(exist_ok=True)
candidates={}
roots=[Path('scripts/construction/evidence'),run/'history',run/'evidence/executed-sources',run/'evidence/coordinator-recovered-source',base]
for root in roots:
 for p in root.rglob('*'):
  if not p.is_file() or '__pycache__'in p.parts or p.suffix not in ['.py','.sh','.c','.h','.patch','.config','.source']:continue
  data=p.read_bytes();sha=hashlib.sha256(data).hexdigest();candidates.setdefault(sha,[]).append(str(p))
records=[]
def hashes(v,path=''):
 if isinstance(v,dict):
  for k,x in v.items():
   key=path+'/'+k
   if k in ['collector_sha256','code_sha256','script_sha256','source_sha256'] and isinstance(x,str) and re.fullmatch('[0-9a-f]{64}',x):yield key,x
   elif k in ['code_hashes','source_hashes'] and isinstance(x,dict):
    for name,sha in x.items():
     if isinstance(sha,str) and re.fullmatch('[0-9a-f]{64}',sha):yield key+'/'+name,sha
   elif isinstance(x,(dict,list)):yield from hashes(x,key)
 elif isinstance(v,list):
  for i,x in enumerate(v):yield from hashes(x,path+'/'+str(i))
for p in sorted(base.rglob('manifest.json')):
 if p.is_symlink():continue
 o=json.loads(p.read_text());bindings=list(hashes(o))
 if not bindings:
  for name in ['observations.json','events.json','evidence.json']:
   f=p.parent/name
   if f.is_file():bindings+=list(hashes(json.loads(f.read_text()),name))
 matched=[]
 for field,sha in dict(bindings).items():
  found=candidates.get(sha,[])
  if found:
   target=store/(sha+'.source')
   if not target.exists():target.write_bytes(Path(found[0]).read_bytes())
  matched.append({'field':field,'sha256':sha,'status':'exact-source-bytes-preserved' if found else 'source-hash-unmatched','source_store_path':str(store/(sha+'.source')) if found else None,'matching_permitted_inputs':found})
 records.append({'bundle':str(p.parent),'manifest_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'recorded_source_hashes':matched,'coverage':'recorded-hashes-only' if bindings else 'no-recognized-source-hash-field','limitation':'Exact byte matching binds only recorded source hashes. Unrecorded dependencies, live source mutation after hash computation and configuration completeness require separate records. No hash match is invented.'})
out={'at':datetime.now(timezone.utc).isoformat(),'status':'provenance-audit-with-explicit-gaps','bundles':records,'source_store_files':len(list(store.glob('*.source'))),'unmatched_recorded_hashes':sum(x['status']=='source-hash-unmatched' for r in records for x in r['recorded_source_hashes']),'bundles_without_recognized_source_hash':sum(not r['recorded_source_hashes'] for r in records),'notes':['Only the permitted current scripts, new-run checkpoints and newly retrieved executed helper files are inspected. No original project, old archive or old history is consulted.','The remote executed mka_events_v5.py was recovered separately because its local pathname was edited after the attempt started. The exporter sanitizer is a separate operation with preserved source.','Public loaded configuration strings and command outputs remain in the immutable per-attempt observations. Credential bytes are never copied into this source store. Missing per-attempt source or configuration bindings remain evidence limitations.']}
if not out['unmatched_recorded_hashes'] and not out['bundles_without_recognized_source_hash']:out['status']='all-recorded-source-hashes-have-preserved-bytes'
(run/'evidence/source-provenance-v3.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({k:v for k,v in out.items() if k not in ['bundles','notes']}))
