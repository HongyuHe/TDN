"""Collect and retain a fresh native and processing snapshot from one benchmark network."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import time

from observe_controls import HERE, NETWORKS
from cohort import SCALE_PREFIXES, registered_profile
from supervisor_transport import call as supervisor_call

ROOT=HERE.parents[2]
REMOTE="""
import io,json,os,sys,subprocess,tarfile,tempfile,time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
request=json.load(sys.stdin)
with tempfile.TemporaryDirectory(prefix='tdn-evidence-') as name:
    root=Path(name); out=root/'snapshot';out.mkdir()
    for filename,text in request['scripts'].items():(root/filename).write_text(text)
    spec=request['profile']['topology'];net=request['profile']['network']
    workers=request.get('workers',1)
    if request.get('read_enclave_policy'):
        sys.path.insert(0,str(root))
        from level_policy import inventory,effective_topology
        policy=inventory(spec)
        (out/'enclave-policy.json').write_text(json.dumps(policy))
        spec=effective_topology(spec,policy)
    def addresses(d):
        return d['id'],json.loads(subprocess.check_output(['docker','exec',d['id'],'ip','-j','-d','address','show']))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        readings=dict(pool.map(addresses,spec['devices']))
    defaults={'gre0','gretap0','erspan0'}
    seen={tuple(sorted(row['ifname'] for row in device if row['ifname'] in defaults)) for device in readings.values()}
    if len(seen)!=1:raise ValueError('Kernel default interfaces differ among the namespaces on one worker')
    platform=','.join(seen.pop())
    spec=capture_topology(spec,readings)
    p=out/'spec.json';p.write_text(json.dumps(spec))
    commands=[[sys.executable,str(root/'collect_native_v2.py'),'--spec',str(p),'--output',str(out/'native'),
               '--configuration-id',net,'--run-id','single-clause','--platform-interface-names',platform,'--skip-active-probes'],
              [sys.executable,str(root/'collect_processing.py'),'--spec',str(p),'--output',str(out/'processing')]]
    def collect(argv):
        if workers>1:argv.extend(['--workers',str(workers)])
        t=time.monotonic();r=subprocess.run(argv,capture_output=True,text=True,timeout=request['collector_timeout'])
        return {'collector':Path(argv[1]).name,'code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'seconds':time.monotonic()-t}
    with ThreadPoolExecutor(max_workers=2) as pool:
        status=list(pool.map(collect,commands))
    (out/'collection.json').write_text(json.dumps(status,indent=2))
    with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as archive:archive.add(out,arcname='snapshot')
"""


def capture(profile,dest):
    if not registered_profile(profile):raise ValueError('Unknown benchmark network')
    dest.mkdir(exist_ok=False,parents=True)
    scripts={n:(ROOT/'scripts/construction/evidence'/n).read_text() for n in ('collect_native_v2.py','collect_processing.py')}
    start=datetime.now(timezone.utc).isoformat();clock=time.monotonic()
    scale=profile['network'] in SCALE_PREFIXES
    if scale:scripts['level_policy.py']=(HERE/'scale/level_policy.py').read_text()
    limit=2500 if scale else 600
    data=json.dumps({'profile':profile,'scripts':scripts,'workers':12 if scale else 1,'collector_timeout':limit,'read_enclave_policy':scale}).encode()
    with tempfile.TemporaryFile() as stream:
        p=supervisor_call(profile['worker'],['sudo','-n','python3','-c',(HERE/'observed_profile.py').read_text()+'\n'+REMOTE],data=data,stream=stream,timeout=limit+650)
        (dest/'collector-stderr.txt').write_bytes(p.stderr)
        if p.returncode:raise RuntimeError(p.stderr[-1000:].decode(errors='replace'))
        stream.seek(0)
        with tarfile.open(fileobj=stream,mode='r:gz') as archive:
            for m in archive:
                relative=Path(m.name)
                if relative.is_absolute() or relative.parts[:1]!=('snapshot',) or '..' in relative.parts:
                    raise ValueError('Unsafe archive member')
                target=dest/relative
                if m.isdir():target.mkdir(parents=True,exist_ok=True)
                elif m.isfile():
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with target.open('xb') as output:
                        import shutil
                        shutil.copyfileobj(archive.extractfile(m),output)
                else:raise ValueError('Unexpected archive entry')
    outputs=json.loads((dest/'snapshot/collection.json').read_text())
    good=all(c['code']==0 for c in outputs) and json.loads(outputs[0]['stdout'])['converged']
    result={'network':profile['network'],'started_at':start,'seconds':time.monotonic()-clock,'converged':good,
            'source_sha256':{n:hashlib.sha256(s.encode()).hexdigest() for n,s in scripts.items()}}
    (dest/'capture.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);p.add_argument('networks',nargs='+',choices=NETWORKS);a=p.parse_args()
    from concurrent.futures import ThreadPoolExecutor
    from cohort import runtime_profile
    def collect(n):return capture(runtime_profile(n),a.directory/n)
    with ThreadPoolExecutor(max_workers=2) as pool:
        for row in pool.map(collect,a.networks):print(row['network'],row['converged'],flush=True)
