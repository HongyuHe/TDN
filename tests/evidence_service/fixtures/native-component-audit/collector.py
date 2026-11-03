#!/usr/bin/env python3
"""Collect public runtime, account, key-access and service inventory for native MSC devices."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

COMMON = {
    'os-release': ['cat','/etc/os-release'],
    'kernel': ['uname','-a'],
    'accounts': ['getent','passwd'],
    'groups': ['getent','group'],
    'dns': ['cat','/etc/resolv.conf'],
    'processes': ['ps','-eo','pid,uid,gid,comm'],
    'listeners': ['ss','-H','-l','-n','-p','-A','all'],
    'clock': ['date','-u','+%Y-%m-%dT%H:%M:%S.%NZ'],
    'time-namespace': ['readlink','/proc/self/ns/time'],
    'packages': ['sh','-c','if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W; elif command -v apk >/dev/null 2>&1; then apk info -vv; else exit 127; fi']}
VPN = {
    'swanctl-version': ['swanctl','--version'],
    'swanctl-commands': ['swanctl','--help'],
    'openssl-version': ['openssl','version','-a'],
    'private-key-access': ['stat','-Lc','%a %u %g %s %n','/etc/swanctl/private/key.pem'],
    'credential-path-access': ['find','/etc/swanctl','-maxdepth','3','-printf','%y %m %U %G %p\n'],
    'vici-socket-access': ['stat','-Lc','%a %u %g %F %n','/var/run/charon.vici']}


def collect(spec_path, output):
    output.mkdir(parents=True,exist_ok=False)
    spec=json.loads(spec_path.read_text());records=[]
    def run(device,kind,args):
        command=(['docker','exec',device] if device else [])+args
        start=datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            result=subprocess.run(command,capture_output=True,text=True,timeout=25)
            stdout,stderr,code=result.stdout,result.stderr,result.returncode
        except subprocess.TimeoutExpired:
            stdout,stderr,code='','timeout',124
        except OSError as error:
            stdout,stderr,code='',str(error),127
        if 'PRIVATE KEY-----' in stdout+stderr:raise ValueError('Secret output refused')
        records.append({'id':'audit-%04d'%len(records),'device':device,'kind':kind,'command':command,
            'startedAt':start,'endedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'returncode':code,'stdout':stdout,'stderr':stderr})
    for device in spec['devices']:
        commands=dict(COMMON)
        if device['role'] in ['inner','outer']:commands.update(VPN)
        for kind,args in commands.items():run(device['id'],kind,args)
    for kind,args in [('host-time-status',['timedatectl','status']),('host-time-show',['timedatectl','show']),
                      ('host-time-namespace',['readlink','/proc/self/ns/time']),('host-ntp',['chronyc','tracking'])]:run(None,kind,args)
    (output/'observations.json').write_text(json.dumps({'records':records,'scope':'Public runtime inventory. Failed commands remain unavailable; file contents of private keys are never read.'},indent=2)+'\n')
    shutil.copy2(spec_path,output/'spec.json');shutil.copy2(__file__,output/'collector.py')
    (output/'manifest.json').write_text(json.dumps({'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(output.iterdir()) if p.is_file()]},indent=2)+'\n')
    print(json.dumps({'records':len(records),'failed':[r['id'] for r in records if r['returncode']]}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--spec',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();collect(args.spec,args.output)
