"""Localize actual Lean premise failures without reading fault manifests or findings."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from common import BASE, ROOT, now, write_json

sys.path.insert(0,str(ROOT/'mcp'))
from tdn_evidence.parsers.correspondence import parse_iptables_save
from tdn_evidence.parsers.execution import rule_json

RUN=BASE/'runs/20261112-blind-theory-01'


def execute(source):
    begin=time.monotonic()
    p=subprocess.run(['lake','env','lean','--json',str(source)],cwd=ROOT,capture_output=True,text=True)
    (source.parent/'typecheck.jsonl').write_text(p.stdout)
    (source.parent/'stderr.txt').write_text(p.stderr)
    messages=[json.loads(line) for line in p.stdout.splitlines() if line.startswith('{')]
    return {'returncode':p.returncode,'runtime_seconds':time.monotonic()-begin,'messages':messages}


def prepare(network):
    data=json.loads((network/'input.json').read_text())
    data['vpnIndices']=[data['deviceIds'][d['id']] for d in data['sourceDevices'] if d['role'] in {'inner','outer'}]
    data['outerIndices']=[data['deviceIds'][d['id']] for d in data['sourceDevices'] if d['role']=='outer']
    write_json(network/'input.json',data)
    diagnostic=network/'diagnostics';diagnostic.mkdir(exist_ok=True);write_json(diagnostic/'input.json',data)
    shutil.copy2(BASE/'RuleDiagnostics.lean',diagnostic/'RuleDiagnostics.lean')
    result=execute(diagnostic/'RuleDiagnostics.lean')
    assert result['returncode']==0,result
    outputs=[json.loads(m['data']) for m in result['messages'] if m['severity']=='information' and m['data'].startswith('[')]
    assert len(outputs)==1,result
    failures=outputs[0]
    reverse={v:k for k,v in data['deviceIds'].items()}
    jobs=[]
    for i,row in enumerate(failures):
        index=row['deviceIndex'];device=data['devices'][index];rule=device[row['chain'].lower()+'Rules'][row['ordinal']]
        ident=f"{network.name}-{i:03}"
        directory=RUN/'local-checks'/ident;directory.mkdir(parents=True,exist_ok=True)
        observation={'kind':row['kind'],'rule':rule,'ifaces':data['ports'],'device':device,'owner':index,'external':'black'}
        write_json(directory/'input.json',{'observation':observation})
        shutil.copy2(BASE/'LocalCompliance.lean',directory/'LocalCompliance.lean')
        metadata={'id':ident,'network':network.name,'device':reverse[index],**row,'rule':rule,'source':str(directory.relative_to(ROOT))}
        write_json(directory/'metadata.json',metadata);jobs.append((directory,metadata))
    write_json(network/'failed-premises.json',failures)
    baseline=json.loads((RUN/'raw/baseline'/f'{network.name}.json').read_text())
    control=json.loads(json.dumps(data))
    for row in baseline['devices']:
        text=row['observations']['firewall4']['stdout']
        import re
        chains=parse_iptables_save(re.sub(r'(?m)^\[\d+:\d+\] ','',text))
        device=control['devices'][data['deviceIds'][row['id']]]
        for chain,record in chains.items():
            device[chain.lower()+'Rules']=[rule_json({'matches':{'iptables_tokens':r['tokens']},'action':r['action'],'ordinal':n,'raw_text':r['raw']}) for n,r in enumerate(record['rules'])]
            device[chain.lower()+'Fallback']={'drop':'deny','accept':'allow'}[record['policy']]
    cdir=RUN/'restored-filter-controls'/network.name;cdir.mkdir(parents=True,exist_ok=True);write_json(cdir/'input.json',control)
    shutil.copy2(BASE/'SnapshotCompliance.lean',cdir/'SnapshotCompliance.lean')
    shutil.copy2(BASE/'RuleDiagnostics.lean',cdir/'RuleDiagnostics.lean')
    write_json(cdir/'provenance.json',{'kind':'controlled replay','description':'Use the observed clean filters with the otherwise unchanged faulty snapshot. No claim that the combined records were collected atomically.'})
    return jobs,cdir


def local_job(job):
    directory,metadata=job;result=execute(directory/'LocalCompliance.lean');record={**metadata,**result}
    write_json(directory/'result.json',record)
    return record


def control_job(directory):
    result=execute(directory/'SnapshotCompliance.lean');write_json(directory/'result.json',result)
    diagnostic=execute(directory/'RuleDiagnostics.lean');write_json(directory/'diagnostic-result.json',diagnostic)
    return {'network':directory.name,'proof':result,'diagnostics':diagnostic}


if __name__=='__main__':
    started=now();clock=time.monotonic()
    with ThreadPoolExecutor(max_workers=3) as pool:prepared=list(pool.map(prepare,sorted((RUN/'tdn').glob('net-*'))))
    jobs=[job for row,_ in prepared for job in row]
    print('Isolated Lean checks:',len(jobs),flush=True)
    with ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(local_job,jobs))
    with ThreadPoolExecutor(max_workers=3) as pool:controls=list(pool.map(control_job,[d for _,d in prepared]))
    write_json(RUN/'local-typechecks.json',{'started_at':started,'ended_at':now(),'runtime_seconds':time.monotonic()-clock,'results':results,'controls':controls})
    print(json.dumps({'local_checks':len(results),'rejected':sum(r['returncode']!=0 for r in results),'control_passes':sum(c['proof']['returncode']==0 for c in controls)}))
