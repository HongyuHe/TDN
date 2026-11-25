"""Validate retained observations, citations, blinding records, and proof outcomes."""
import hashlib
import json
import re
from pathlib import Path
from historical_paths import historical_path
import pymupdf
from common import BASE, ROOT, now, write_json

r=BASE/'runs/20261112-blind-theory-01'
freeze=json.loads((r/'tdn-results-freeze.json').read_text())
for name,digest in freeze['hashes'].items():
    assert hashlib.sha256(historical_path(name).read_bytes()).hexdigest()==digest,name
pdf=pymupdf.open(ROOT/'docs/CSfC_documentation_v1.3.0.pdf')
def normalize(s):
    return re.sub(r'(?<=-)\s+','',re.sub(r'\s+',' ',s)).strip()
records=[]
for model in ['astra','sol']:
    findings=json.loads((r/model/'output/findings.json').read_text())['findings']
    obs={p.stem:json.loads(p.read_text()) for p in (r/model/'detector-session/observations').glob('*.json')}
    calls=json.loads((r/model/'tool-calls.json').read_text())
    workspace=next(x['workspace'] for x in json.loads((r/'detector-workspaces.json').read_text()) if x['model']==model)
    text='\n'.join(c['arguments'] if isinstance(c['arguments'],str) else json.dumps(c['arguments']) for c in calls)
    absolute=set(re.findall(r'/(?:Users|tmp|private)/[^\s"\'`<>;\\]+',text))
    assert all(p.startswith(workspace) for p in absolute),(model,absolute)
    assert all(c['name']=='exec' for c in calls)
    requests=[json.loads(line) for line in (r/model/'detector-session/requests.jsonl').read_text().splitlines()]
    assert all(x['method']=='GET' and x['path'].startswith('/api') for x in requests)
    for f in findings:
        assert normalize(f['source_quote']) in normalize(pdf[f['pdf_page']-1].get_text()),f['id']
        assert f['observation_ids'],f['id']
        for oid in f['observation_ids']:
            assert oid in obs or oid=='inventory',(f['id'],oid)
        records.append({'model':model,'finding':f['id'],'quote_matches_pdf':True,'observation_ids_present':True})
    write_json(r/model/'access-audit.json',{'at':now(),'tool_calls_reviewed':len(calls),'unauthorized_access_observed':False,
        'method':'Reviewed recorded commands, generated script paths, and gateway requests. All explicit task-file paths stay in the assigned workspace and every network request uses the allowlisted gateway.',
        'enforcement':'Instruction-based filesystem restriction and retrospective tool/script audit; not an OS sandbox. Network access is constrained by the command gateway.',
        'failed_ssh_observations':sum(o['returncode']==255 for o in obs.values())})
finding_checks=len(records)
for phase,expected in [('corrected',True),('clean-repeat',False),('final-restored',True)]:
    rows=[v for p in (r/'raw/oracle'/phase).glob('*.json') for v in json.loads(p.read_text())['records']]
    assert len(rows)==100 and all(v['status']=='observed' and v['violated']==expected for v in rows)
    records.append({'phase':phase,'live_checks':len(rows),'behavior_matches_injection_state':True})
clean=json.loads((r/'clean-tdn-typechecks.json').read_text())
faulty=json.loads((r/'tdn-typechecks.json').read_text())
assert len(clean)==len(faulty)==5
assert all(x['returncode']==0 and not x['errors'] for x in clean)
assert all(x['returncode']==1 and len(x['errors'])==1 and 'TableDrivenForwardChecks' in x['errors'][0]['data'] for x in faulty)
local=json.loads((r/'local-typechecks.json').read_text())
assert len(local['results'])==65
assert all(x['returncode']==1 and any(m['severity']=='error' and 'evaluated that the proposition' in m['data'] and 'is false' in m['data'] for m in x['messages']) for x in local['results'])
assert len(local['controls'])==5 and all(x['proof']['returncode']==0 for x in local['controls'])
headers=json.loads((r/'header-typechecks.json').read_text())
assert len(headers)==10
assert sum(x['phase']=='clean-tdn' and x['returncode']==0 for x in headers)==5
assert sum(x['phase']=='tdn' and x['returncode']==1 and len([m for m in x['messages'] if m['severity']=='error'])==2 for x in headers)==5
summary={'citation_and_evidence_checks':finding_checks,'live_behavior_checks':300,
 'clean_Lean_passes':5,'faulty_Lean_rejections':5,'isolated_Lean_rejections':65,
 'clean_filter_replay_passes':5,'clean_header_proof_passes':5,'faulty_header_proof_rejections':5}
write_json(r/'validation.json',{'at':now(),'checks':records,'clean_full_snapshot_typechecks_passed':5,'faulty_full_snapshot_typechecks_rejected':5,
 'condition':'All observed before/after behaviors checked. Semantic ground truth for net-04 PF-18 remains qualified in scoring.json.',
 'tdn_frozen_before_agent_findings_opened':True,'tdn_freeze_hashes_match':True,'summary':summary})
print(json.dumps(summary))
