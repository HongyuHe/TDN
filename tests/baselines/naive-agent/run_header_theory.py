"""Validate the already frozen protocol and multicast conditions as full hook theorems."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
from common import BASE, write_json
from localize_theory_errors import execute
r=BASE/'runs/20261112-blind-theory-01'
jobs=[]
for phase in ['tdn','clean-tdn']:
    for directory in sorted((r/phase).glob('net-*')):
        data=json.loads((directory/'input.json').read_text())
        data['vpnIndices']=[data['deviceIds'][d['id']] for d in data['sourceDevices'] if d['role'] in {'inner','outer'}]
        data['outerIndices']=[data['deviceIds'][d['id']] for d in data['sourceDevices'] if d['role']=='outer']
        target=r/'header-typechecks'/phase/directory.name;target.mkdir(parents=True,exist_ok=True)
        write_json(target/'input.json',data);shutil.copy2(BASE/'HeaderCompliance.lean',target/'HeaderCompliance.lean');jobs.append(target)
def run(p):
    result=execute(p/'HeaderCompliance.lean');write_json(p/'result.json',result)
    return {'phase':p.parent.name,'network':p.name,**result}
with ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(run,jobs))
write_json(r/'header-typechecks.json',results)
print(json.dumps([(x['phase'],x['network'],x['returncode']) for x in results]))
