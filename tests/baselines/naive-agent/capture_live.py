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
from supervisor_transport import call as supervisor_call

ROOT=HERE.parents[2]
REMOTE="""
import io,json,os,sys,subprocess,tarfile,tempfile,time
from pathlib import Path
request=json.load(sys.stdin)
with tempfile.TemporaryDirectory(prefix='tdn-evidence-') as name:
    root=Path(name); out=root/'snapshot';out.mkdir()
    for filename,text in request['scripts'].items():(root/filename).write_text(text)
    spec=request['profile']['topology'];net=request['profile']['network']
    for d in spec['devices']:
        raw=subprocess.check_output(['docker','exec',d['id'],'ip','-j','-d','address','show'])
        known={i['name'] for i in d['interfaces']}
        for row in json.loads(raw):
            if row['ifname'] not in known and row.get('linkinfo',{}).get('info_kind')=='dummy':
                d['interfaces'].append({'name':row['ifname'],'zone':'local','mtu':row['mtu']})
    p=out/'spec.json';p.write_text(json.dumps(spec))
    commands=[[sys.executable,str(root/'collect_native_v2.py'),'--spec',str(p),'--output',str(out/'native'),
               '--configuration-id',net,'--run-id','single-clause','--platform-interface-names','gre0,gretap0,erspan0','--skip-active-probes'],
              [sys.executable,str(root/'collect_processing.py'),'--spec',str(p),'--output',str(out/'processing')]]
    status=[]
    for argv in commands:
        t=time.monotonic();r=subprocess.run(argv,capture_output=True,text=True,timeout=600)
        status.append({'collector':Path(argv[1]).name,'code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'seconds':time.monotonic()-t})
    (out/'collection.json').write_text(json.dumps(status,indent=2))
    with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as archive:archive.add(out,arcname='snapshot')
"""


def capture(profile,dest):
    if profile['network'] not in NETWORKS:raise ValueError('Unknown benchmark network')
    dest.mkdir(exist_ok=False,parents=True)
    scripts={n:(ROOT/'scripts/construction/evidence'/n).read_text() for n in ('collect_native_v2.py','collect_processing.py')}
    start=datetime.now(timezone.utc).isoformat();clock=time.monotonic()
    data=json.dumps({'profile':profile,'scripts':scripts}).encode()
    with tempfile.TemporaryFile() as stream:
        p=supervisor_call(profile['worker'],['sudo','-n','python3','-c',REMOTE],data=data,stream=stream,timeout=1250)
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
    def collect(n):return capture(json.loads((HERE/'profiles'/(n+'.json')).read_text()),a.directory/n)
    with ThreadPoolExecutor(max_workers=2) as pool:
        for row in pool.map(collect,a.networks):print(row['network'],row['converged'],flush=True)
