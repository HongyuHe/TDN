#!/usr/bin/env python3
"""Collect peer-bound MKA settings in isolated Linux namespaces."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time


def utc():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    private = Path(tempfile.mkdtemp(prefix='tdn-mka-private-'))
    private.chmod(0o700)
    token = 't32m' + secrets.token_hex(3)
    nodes, pids, records = [], [], []
    cak, ckn = secrets.token_hex(32), secrets.token_hex(32)
    started, error = utc(), None

    def sanitized(text):
        text = text.replace(cak, '[REDACTED_CAK]')
        return re.sub(r'(hexdump(?:_ascii)?(?:\([^\n]*?\))?:)[^\n]*', r'\1 [REDACTED]', text)

    def run(command, check=True):
        begin = utc()
        result = subprocess.run([str(arg) for arg in command], capture_output=True, text=True, timeout=20)
        record = {'id': f'mka-{len(records):03d}', 'command': [str(arg) for arg in command],
                  'started_at': begin, 'ended_at': utc(), 'returncode': result.returncode,
                  'stdout': sanitized(result.stdout), 'stderr': sanitized(result.stderr)}
        records.append(record)
        if check and result.returncode:
            raise RuntimeError(f'{command[0]} failed in observation {record["id"]}: {record["stderr"]}')
        return result

    def ns(node, *command, check=True):
        return run(['ip', 'netns', 'exec', node, *command], check)

    try:
        run(['uname', '-a'])
        run(['ip', '-Version'])
        run(['sha256sum', args.binary])
        for suffix in ['a', 'b']:
            node = token + '-' + suffix
            run(['ip', 'netns', 'add', node])
            nodes.append(node)
            ns(node, 'ip', 'link', 'set', 'lo', 'up')
        run(['ip', 'link', 'add', token + 'a', 'type', 'veth', 'peer', 'name', token + 'b'])
        for index, node in enumerate(nodes):
            raw = token + ['a', 'b'][index]
            run(['ip', 'link', 'set', raw, 'netns', node])
            ns(node, 'ip', 'link', 'set', raw, 'name', 'eth0')
            ns(node, 'ip', 'link', 'set', 'eth0', 'up')
            ctrl = private / f'ctrl{index}'
            ctrl.mkdir()
            conf = private / f'peer{index}.conf'
            text = f'''ctrl_interface={ctrl}
eapol_version=3
ap_scan=0
network={{
 key_mgmt=NONE
 eapol_flags=0
 macsec_policy=1
 macsec_integ_only=0
 macsec_replay_protect=1
 macsec_replay_window=2
 macsec_csindex=1
 mka_cak={cak}
 mka_ckn={ckn}
 mka_priority={index}
}}
'''
            conf.write_text(text)
            conf.chmod(0o600)
            (args.output / f'peer{index}.conf.public').write_text(sanitized(text))
            pidfile = private / f'peer{index}.pid'
            ns(node, args.binary, '-d', '-B', '-D', 'macsec_linux', '-i', 'eth0',
               '-c', conf, '-P', pidfile, '-f', private / f'peer{index}.log')
            for _ in range(20):
                if pidfile.exists():
                    break
                time.sleep(0.1)
            pids.append(int(pidfile.read_text()))
        time.sleep(7)
        for index, node in enumerate(nodes):
            ns(node, 'wpa_cli', '-p', private / f'ctrl{index}', '-i', 'eth0', 'status')
            ns(node, 'ip', '-s', 'macsec', 'show')
            links = json.loads(ns(node, 'ip', '-j', '-d', 'link').stdout)
            iface = next(row['ifname'] for row in links if row.get('linkinfo', {}).get('info_kind') == 'macsec')
            ns(node, 'ip', 'addr', 'add', f'10.91.0.{index + 1}/30', 'dev', iface)
            ns(node, 'ip', 'link', 'set', iface, 'up')
        result = ns(nodes[0], 'ping', '-n', '-c', '3', '-W', '1', '10.91.0.2', check=False)
        records[-1].update(probe='protected-data', observed_result='delivered' if result.returncode == 0 else 'no_reply')
        for index, node in enumerate(nodes):
            ns(node, 'wpa_cli', '-p', private / f'ctrl{index}', '-i', 'eth0', 'mib')
            run(['cat', private / f'peer{index}.log'])
    except Exception as exc:
        error = str(exc)
    finally:
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        time.sleep(0.2)
        for node in nodes:
            run(['ip', 'netns', 'delete', node], check=False)
        shutil.rmtree(private)
    document = {'schema_version': 'csfc-authentication-events/v1', 'started_at': started, 'ended_at': utc(),
                'runtime_backend': 'supplemental-Linux-network-namespaces', 'authentication': 'MKA PSK',
                'mode': 'instrumented-bounded-replay-two', 'records': records, 'error': error,
                'public_settings': {'replay_window': 2, 'confidentiality_offset': 0},
                'limitations': ['Instrumented daemon and isolated namespaces.', 'No NSA key-generator or product approval.',
                               'Observed settings and selected packets do not prove all daemon behavior.']}
    (args.output / 'events.json').write_text(json.dumps(document, indent=2) + '\n')
    shutil.copy2(__file__, args.output / 'collector.source.py')
    manifest = {'schema_version': document['schema_version'], 'files': [
        {'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size}
        for path in sorted(args.output.iterdir()) if path.is_file()]}
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'error': error, 'records': len(records)}))
    if error:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
