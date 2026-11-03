#!/usr/bin/env python3
"""Read active native IPsec state and compare private peer keys without exporting them."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def state_records(text):
    result = []
    for block in re.split(r'(?m)(?=^src )', text):
        if not block.strip():
            continue
        endpoints = re.search(r'^src (\S+) dst (\S+)', block)
        identity = re.search(r'proto (\S+) spi (0x[0-9a-f]+)(?:\(\d+\))? reqid (\d+)(?:\(0x[0-9a-f]+\))? mode (\S+)', block)
        if endpoints is None or identity is None:
            raise ValueError('Unsupported XFRM state identity')
        materials, public = [], block
        for match in re.finditer(r'(?m)^\s*(aead|auth-trunc|auth|enc)\s+(\S+)\s+(0x[0-9a-f]+)([^\n]*)$', block):
            kind, algorithm, encoded, parameters = match.groups()
            raw = bytes.fromhex(encoded[2:])
            if not raw:
                raise ValueError('Empty installed cryptographic key')
            materials.append((kind, algorithm, raw, parameters.strip()))
            public = public.replace(encoded, '[PRIVATE_MATERIAL_REDACTED]')
        if not materials or re.search(r'0x[0-9a-fA-F]{32,}', public):
            raise ValueError('Unrecognized private XFRM material; no raw state exported')
        protocol, spi, reqid, mode = identity.groups()
        result.append({'source': endpoints[1], 'destination': endpoints[2], 'protocol': protocol,
            'spi': int(spi, 16), 'reqid': int(reqid), 'mode': mode,
            'mark': re.search(r'(?m)^\s*mark (\S+)', public).group(1) if re.search(r'(?m)^\s*mark (\S+)', public) else None,
            'ifId': re.search(r'(?m)^\s*if_id (\S+)', public).group(1) if re.search(r'(?m)^\s*if_id (\S+)', public) else None,
            'publicBlock': public, 'privateMaterials': materials})
    return result


def capture(spec_path, output):
    output.mkdir(parents=True, exist_ok=False)
    spec = json.loads(spec_path.read_text())
    devices = [d for d in spec['devices'] if d['role'] in ['inner', 'outer']]
    observations, phases, errors = [], [], []
    private_materials = {}
    started = now()

    def observe(device, name, argv):
        command = ['docker', 'exec', device, *argv]
        start = now()
        process = subprocess.run(command, capture_output=True, text=True, timeout=25)
        if 'PRIVATE KEY-----' in process.stdout or 'PRIVATE KEY-----' in process.stderr:
            raise ValueError('Private certificate key refused')
        row = {'id': 'obs-%04d' % len(observations), 'device': device, 'kind': name, 'command': command,
            'startedAt': start, 'endedAt': now(), 'returncode': process.returncode,
            'stdout': process.stdout, 'stderr': process.stderr}
        observations.append(row)
        if process.returncode:
            raise ValueError('Observation failed: ' + row['id'] + '/' + name)
        return row

    try:
        for phase_number in range(2):
            phase = {'id': 'phase-' + str(phase_number), 'startedAt': now(), 'devices': [], 'bindings': []}
            for device in devices:
                name = device['id']
                record = {'id': name, 'role': device['role'], 'observations': {}}
                for kind, argv in [
                    ('interfaces', ['ip', '-j', 'addr']),
                    ('sas', ['swanctl', '--list-sas', '--raw']),
                    ('states', ['ip', 'xfrm', 'state', 'list', 'nokeys']),
                    ('statistics', ['env', 'TZ=UTC', 'ip', '-s', 'xfrm', 'state', 'list', 'nokeys']),
                    ('policies', ['ip', 'xfrm', 'policy']),
                    ('connections', ['swanctl', '--list-conns', '--raw']),
                    ('configuration', ['cat', '/etc/swanctl/swanctl.conf'])]:
                    record['observations'][kind] = observe(name, kind, argv)['id']
                interface_row = next(r for r in observations if r['id'] == record['observations']['interfaces'])
                addresses = {a['local']: p['ifname'] for p in json.loads(interface_row['stdout'])
                    for a in p.get('addr_info', []) if a['family'] in ['inet', 'inet6']}
                start = now()
                command = ['docker', 'exec', name, 'ip', 'xfrm', 'state']
                process = subprocess.run(command, text=True, capture_output=True, timeout=20)
                if process.returncode:
                    raise ValueError('Private-state read failed; output omitted')
                states = state_records(process.stdout)
                observation_id = 'obs-%04d' % len(observations)
                observations.append({'id': observation_id, 'device': name, 'kind': 'private-state-comparison',
                    'command': command, 'startedAt': start, 'endedAt': now(), 'returncode': 0,
                    'stdout': '\n'.join(state['publicBlock'] for state in states), 'stderr': '',
                    'transformation': 'Key values compared in process memory; only public hashes, lengths and equality links are retained.'})
                record['observations']['materialRead'] = observation_id
                for index, state in enumerate(states):
                    material = state.pop('privateMaterials')
                    incoming, outgoing = state['destination'] in addresses, state['source'] in addresses
                    if incoming == outgoing:
                        raise ValueError('IPsec direction is not uniquely bound to a local interface')
                    identifier = phase['id'] + ':' + name + ':' + str(index)
                    private_materials[identifier] = material
                    phase['bindings'].append(state | {'id': identifier, 'device': name,
                        'direction': 'inbound' if incoming else 'outbound',
                        'localInterface': addresses[state['destination'] if incoming else state['source']],
                        'materialObservation': observation_id, 'publicStateObservation': record['observations']['states'],
                        'statisticsObservation': record['observations']['statistics'], 'materials': [
                            {'kind': kind, 'algorithm': algorithm, 'bytes': len(key),
                             'sha256': hashlib.sha256(key).hexdigest(), 'parameters': parameters}
                            for kind, algorithm, key, parameters in material]})
                if not states:
                    raise ValueError('No active installed associations for ' + name)
                if phase_number == 0:
                    for kind, argv in [
                        ('certificates', ['swanctl', '--list-certs', '--raw']),
                        ('leafCertificate', ['cat', '/etc/swanctl/x509/cert.pem']),
                        ('caCertificate', ['cat', '/etc/swanctl/x509ca/ca.pem']),
                        ('crl', ['cat', '/etc/swanctl/x509crl/ca.crl.pem']),
                        ('ikeLog', ['cat', '/tmp/charon.log'])]:
                        record['observations'][kind] = observe(name, kind, argv)['id']
                phase['devices'].append(record)
            for binding in phase['bindings']:
                peers = [p for p in phase['bindings'] if p['device'] != binding['device'] and
                    p['direction'] != binding['direction'] and all(p[k] == binding[k]
                        for k in ['source', 'destination', 'protocol', 'spi', 'mode'])]
                if len(peers) != 1:
                    raise ValueError('No unique installed peer association')
                peer = peers[0]
                if private_materials[binding['id']] != private_materials[peer['id']]:
                    raise ValueError('Active peer private material differs')
                binding['equalTo'] = peer['id']
            phase['endedAt'] = now()
            phases.append(phase)
            time.sleep(.2)
    except Exception as error:
        errors.append(str(error))
    finally:
        private_materials.clear()
        (output / 'observations.json').write_text(json.dumps(observations, indent=2) + '\n')
        (output / 'spec.json').write_text(json.dumps(spec, indent=2) + '\n')
        (output / 'correlation.json').write_text(json.dumps({'schema': 'native-ipsec-correlation/v1',
            'startedAt': started, 'endedAt': now(), 'phases': phases, 'errors': errors,
            'equalityMethod': 'Direct equality of algorithm, key bytes and parameters read from both active kernel associations in collector memory.',
            'scope': 'Sequential observations with an explicit before/after comparison; no atomic multi-device capture claim.'}, indent=2) + '\n')
        shutil.copy2(__file__, output / 'collector.source.py')
        files = [{'path': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size}
                 for p in sorted(output.iterdir()) if p.is_file()]
        (output / 'manifest.json').write_text(json.dumps({'schema': 'native-ipsec-correlation/v1',
            'configuration_id': output.name, 'files': files, 'errors': errors}, indent=2) + '\n')
    if errors:
        raise RuntimeError('; '.join(errors))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    capture(args.spec, args.output)
