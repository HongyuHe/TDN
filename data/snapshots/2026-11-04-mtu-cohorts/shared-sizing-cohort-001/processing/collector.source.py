#!/usr/bin/env python3
"""Collect the read-only processing observations required by the execution export."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


COMMANDS = {
    'all-tables4': ['iptables-save'],
    'all-tables6': ['ip6tables-save'],
    'policy-routing4': ['ip', '-j', '-4', 'rule', 'show'],
    'policy-routing6': ['ip', '-j', '-6', 'rule', 'show'],
    'routes4': ['ip', '-j', '-4', 'route', 'show', 'table', 'all'],
    'routes6': ['ip', '-j', '-6', 'route', 'show', 'table', 'all'],
    'xfrm-policies-detailed': ['ip', '-d', 'xfrm', 'policy', 'list'],
    'xfrm-states-detailed-nokeys': ['ip', '-d', '-s', 'xfrm', 'state', 'list', 'nokeys'],
    'xfrm-policy-main': ['ip', '-d', 'xfrm', 'policy', 'list', 'ptype', 'main'],
    'xfrm-policy-sub': ['ip', '-d', 'xfrm', 'policy', 'list', 'ptype', 'sub'],
    'xfrm-stat': ['cat', '/proc/net/xfrm_stat'],
    'addresses': ['ip', '-j', '-d', 'address', 'show'],
    'processes': ['ps', '-eo', 'pid,comm'],
    'sockets': ['ss', '-H', '-a', '-n', '-p', '-A', 'all']}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def collect(spec_path, output):
    output.mkdir(parents=True, exist_ok=False)
    spec = json.loads(spec_path.read_text())
    devices = [d['id'] for d in spec['devices']]
    started, records, failures = now(), [], []
    for phase in ['before', 'after']:
        for device in devices:
            commands = dict(COMMANDS)
            for kind, arguments in commands.items():
                command = ['docker', 'exec', device, *arguments]
                beginning = now()
                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=25)
                    stdout, stderr, code = result.stdout, result.stderr, result.returncode
                except subprocess.TimeoutExpired:
                    stdout, stderr, code = '', 'Collector timeout', 124
                if 'PRIVATE KEY-----' in stdout or 'PRIVATE KEY-----' in stderr:
                    raise ValueError('Private key output refused')
                record = {'id': 'processing-%05d' % len(records), 'phase': phase, 'device_id': device,
                    'kind': kind, 'command': command, 'started_at': beginning, 'ended_at': now(),
                    'returncode': code, 'stdout': stdout, 'stderr': stderr}
                records.append(record)
                if code:
                    failures.append(record['id'])
    ended = now()
    observations = {'schema_version': 'processing-evidence/v1', 'request_id': output.name,
        'started_at': started, 'ended_at': ended, 'runtime_backend': 'native-frr-ovs-strongswan-linux',
        'expected_device_ids': devices, 'records': records,
        'limitations': ['Sequential before/after observations do not prove atomicity.']}
    (output / 'observations.json').write_text(json.dumps(observations, indent=2) + '\n')
    shutil.copy2(__file__, output / 'collector.source.py')
    files = [{'path': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size}
             for p in sorted(output.iterdir()) if p.is_file()]
    manifest = {'started_at': started, 'ended_at': ended, 'request_id': output.name,
        'collector_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'spec_sha256': hashlib.sha256(spec_path.read_bytes()).hexdigest(), 'files': files, 'failures': failures}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'records': len(records), 'failures': failures}))
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    collect(arguments.spec, arguments.output)
