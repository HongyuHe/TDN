import hashlib,json,shutil
from pathlib import Path
from datetime import datetime,timezone
run=Path('artifacts/construction/2026-10-24T014455Z');base=Path('artifacts/snapshots/2026-10-24T014455Z');out=base/'assessment-and-replay-v7';out.mkdir();source=Path('scripts/construction/evidence')
paths=[run/'evidence/assessment-all76-v3.json',run/'evidence/completion_assessment.md',run/'evidence/case_coverage_v3.json',run/'evidence/case_coverage.md',run/'evidence/WORK_QUEUE.md',run/'evidence/source-provenance-v3.json',run/'PROGRESS.md',source/'README.md',source/'REPLAY.md',source/'profiles/README.md',source/'profiles/replay-native-freebsd-v7.json']
for p in paths:
 target=out/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(p.read_bytes())
assessment=json.loads((run/'evidence/assessment-all76-v3.json').read_text());coverage=json.loads((run/'evidence/case_coverage_v3.json').read_text());audit=json.loads((run/'evidence/source-provenance-v3.json').read_text());assert len(assessment['groups'])==76 and coverage['case_count']==59;assert all(c['availability']=='present'for c in coverage['cases']);assert not audit['unmatched_recorded_hashes']and not audit['bundles_without_recognized_source_hash']
published={}
def values(o):
 if isinstance(o,dict):
  for x in o.values():yield from values(x)
 elif isinstance(o,list):
  for x in o:yield from values(x)
 elif isinstance(o,str)and o.startswith('artifacts/snapshots/'):yield o
for response in sorted((run/'responses').glob('*.json')):
 try:obj=json.loads(response.read_text())
 except Exception:continue
 for path in values(obj):
  if Path(path).exists():published.setdefault(path,[]).append(str(response))
case_checks=[]
for c in coverage['cases']:
 path=c['snapshot_path'];matches=[{'published_path':p,'response_paths':r}for p,r in published.items()if path==p or path.startswith(p+'/')]
 case_checks.append({'coverage_id':c['coverage_id'],'path':path,'ready_response_matches':matches})
assert all(c['ready_response_matches']for c in case_checks),[c['coverage_id']for c in case_checks if not c['ready_response_matches']]
(out/'case-handoff-audit.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'cases':case_checks,'missing_ready_responses':0},indent=2)+'\n')
(out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':str(p.relative_to(out)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.rglob('*')if p.is_file()]},indent=2)+'\n')
response={'id':'ASSESSMENT-REPLAY-v7','at':datetime.now(timezone.utc).isoformat(),'status':'ready-coherent-working-assessment-actionable-work-remains','bundle_paths':[str(out)],'checks':{'groups':76,'source_passages':sum(len(g['clauses'])for g in assessment['groups']),'representative_cases':59,'missing_case_handoffs':0,'source_versions':audit['source_store_files'],'unmatched_recorded_hashes':0},'scope':'Working evidence-side assessment and current tested replay instructions. Completed finite observations, preserved counterexamples, exact source availability, optional management scope and remaining implementation/external records remain distinct. Construction owns all formal proof accounting. No whole-group or overall completion is claimed.'}
(run/'responses/ASSESSMENT-REPLAY-v7.json').write_text(json.dumps(response,indent=2)+'\n');print(str(run/'responses/ASSESSMENT-REPLAY-v7.json'))
