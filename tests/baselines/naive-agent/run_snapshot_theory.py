"""Typecheck unchanged general TDN proofs with fresh concrete snapshot inputs."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
from common import BASE, ROOT, now, write_json


def run_job(directory):
    template=BASE/'SnapshotCompliance.lean'
    source=directory/'SnapshotCompliance.lean'
    shutil.copy2(template,source)
    started=now();clock=time.monotonic()
    result=subprocess.run(['lake','env','lean','--json',str(source)],cwd=ROOT,capture_output=True,text=True)
    (directory/'typecheck.jsonl').write_text(result.stdout)
    (directory/'typecheck-stderr.txt').write_text(result.stderr)
    errors=[]
    for line in result.stdout.splitlines():
        try:
            item=json.loads(line)
            if item.get('severity')=='error':errors.append(item)
        except ValueError:pass
    record={'network':directory.name,'started_at':started,'ended_at':now(),'runtime_seconds':time.monotonic()-clock,
            'returncode':result.returncode,'errors':errors,'input_sha256':hashlib.sha256((directory/'input.json').read_bytes()).hexdigest(),
            'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest()}
    write_json(directory/'typecheck-result.json',record)
    print(json.dumps({'network':directory.name,'returncode':result.returncode,'errors':len(errors),'seconds':record['runtime_seconds']}),flush=True)
    return record


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('run_id');a=p.parse_args();root=BASE/'runs'/a.run_id
    with ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(run_job,sorted((root/'tdn').glob('net-*'))))
    write_json(root/'tdn-typechecks.json',results)
