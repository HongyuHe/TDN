"""Preserve blind Detector outputs and runtime without displaying their findings."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import shutil
import tarfile
from common import BASE, now, sha256, write_json

p=argparse.ArgumentParser();p.add_argument('model');p.add_argument('trace',type=Path);a=p.parse_args()
run=BASE/'runs/20261112-blind-theory-01'
row=next(r for r in json.loads((run/'detector-workspaces.json').read_text()) if r['model']==a.model)
workspace=Path(row['workspace']);target=run/a.model
records=[json.loads(line) for line in a.trace.read_text().splitlines()]
events=[r for r in records if r['type']=='event_msg']
started=next(r['timestamp'] for r in events if r['payload'].get('type')=='task_started')
ended=[r['timestamp'] for r in events if r['payload'].get('type')=='task_complete'][-1]
context=next(r['payload'] for r in records if r['type']=='turn_context')
calls=[{'timestamp':r['timestamp'],'name':r['payload']['name'],'arguments':r['payload'].get('input',r['payload'].get('arguments'))} for r in records if r['type']=='response_item' and r['payload'].get('type') in {'custom_tool_call','function_call'}]
token=json.loads((workspace/'access.json').read_text())['token']
assert token not in json.dumps(calls)
shutil.copytree(workspace/'output',target/'output')
with tarfile.open(target/'derived-records.tar.gz','w:gz') as archive:
    for source in sorted((workspace/'scratch').rglob('*')):
        if source.is_file() and '__pycache__' not in source.parts:
            assert token.encode() not in source.read_bytes()
            archive.add(source,arcname=str(source.relative_to(workspace)))
write_json(target/'tool-calls.json',calls)
observations=list((target/'detector-session/observations').glob('*.json'))
requests=(target/'detector-session/requests.jsonl').read_text().splitlines()
duration=(datetime.fromisoformat(ended.replace('Z','+00:00'))-datetime.fromisoformat(started.replace('Z','+00:00'))).total_seconds()
write_json(target/'runtime.json',{'recorded_at':now(),'started_at':started,'ended_at':ended,'runtime_seconds':duration,
 'model':context['model'],'reasoning_effort':context.get('effort'),'tool_invocations':len(calls),'gateway_requests':len(requests),'device_observations':len(observations),
 'trace_sha256':sha256(a.trace.read_bytes()),'findings_sha256':sha256((target/'output/findings.json').read_bytes())})
print(json.dumps({'model':context['model'],'reasoning_effort':context.get('effort'),'runtime_seconds':duration,'tool_invocations':len(calls)}))
