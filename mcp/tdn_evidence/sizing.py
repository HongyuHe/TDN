"""Expose observed native packet lengths, fragmentation and source errors."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ['devices', 'interfaces', 'cases', 'packets', 'configuration']
LEAN_VIEW = 'native_packet_sizing'
SCOPE = 'Observed IPv4 ICMP boundary probes and ESP fragments on one native path'


def packet_fields(frame):
    require(len(frame) >= 34 and frame[12:14] == b'\x08\x00', 'Expected captured IPv4 frame')
    raw = frame[14:]
    header, length = (raw[0] & 15) * 4, int.from_bytes(raw[2:4], 'big')
    require(raw[0] >> 4 == 4 and 20 <= header <= length <= len(raw), 'Invalid captured IPv4 length')
    flags = int.from_bytes(raw[6:8], 'big')
    return {'frame_bytes': len(frame), 'ip_bytes': length, 'ip_header_bytes': header,
        'protocol': raw[9], 'source': str(ipaddress.IPv4Address(raw[12:16])),
        'destination': str(ipaddress.IPv4Address(raw[16:20])), 'ip_id': int.from_bytes(raw[4:6], 'big'),
        'df': bool(flags & 0x4000), 'mf': bool(flags & 0x2000), 'fragment_offset': (flags & 8191) * 8,
        'ip_sha256': hashlib.sha256(raw[:length]).hexdigest(), 'payload_hex': raw[header:length].hex()}


def parse(directory):
    directory = Path(directory)
    manifest_hash = validate_files(directory)
    manifest = json.loads((directory / 'manifest.json').read_text())
    evidence = json.loads((directory / 'cases.json').read_text())
    commands = json.loads((directory / 'commands.json').read_text())
    spec = json.loads((directory / 'spec.json').read_text())
    require(manifest['schema'] == 'native-packet-sizing/v1', 'Unsupported sizing capture')
    by_id = {c['id']: c for c in commands}
    require(len(by_id) == len(commands), 'Duplicate sizing observation')
    devices = {d['id']: d for d in spec['devices']}
    source = evidence['source']
    require(source in devices and len(evidence['cases']) == 5, 'Incomplete native sizing experiment')
    packets, interfaces, configuration, raw_ids = [], [], [], set()
    for command in commands:
        kind = command['kind']
        if kind == 'packet-observer':
            device, port = command['device'], command['interface']
            require(device in devices and port in {i['name'] for i in devices[device]['interfaces']},
                    'Packet observer is outside the declared interface inventory')
            require(command['stderr'] == '' and command['stopped_by_collector'] and command['returncode'] in [-15, 0],
                    'Packet observer failed')
            path = directory / command['output']
            path.resolve().relative_to(directory.resolve())
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            require(rows and rows[0].get('ready') and rows[0]['interface'] == port, 'Observer was not ready')
            require(all(a['monotonic_ns'] <= b['monotonic_ns'] for a, b in zip(rows, rows[1:])),
                    'Packet observation order differs')
            for index, row in enumerate(rows[1:]):
                require(row['interface'] == port and row['packet_type'] in [0, 4], 'Unsupported packet observer direction')
                derived = packet_fields(bytes.fromhex(row['frame_hex']))
                require(all(row.get(key) == value for key, value in derived.items() if key != 'payload_hex'),
                        'Captured packet metadata differs from bytes')
                packets.append(row | derived | {'id': command['id'] + ':' + str(index),
                    'device': device, 'observation': command['id']})
        elif kind == 'interface-mtu':
            require(command['returncode'] == 0, 'Failed MTU observation')
            values = json.loads(command['stdout'])
            require(len(values) == 1, 'Ambiguous MTU interface')
            interface = values[0]
            device, port = command['command'][2], command['command'][-1]
            require(interface['ifname'] == port and command['command'][:3] == ['docker', 'exec', device],
                    'MTU observation identity differs')
            interfaces.append({'device': device, 'name': port, 'mtu': interface['mtu'],
                'observed': interface, 'observation': command['id']})
        elif kind in ['offload', 'pmtu', 'routes', 'counters-before', 'counters-after', 'filters-before', 'filters-after']:
            require(command['returncode'] == 0, 'Failed sizing configuration observation')
            configuration.append(command)
        raw_ids.add(command['id'])
    cases = []
    require(packets and interfaces, 'Missing sizing observations')
    for case in evidence['cases']:
        command = by_id[case['observation']]
        require(command['kind'] == 'probe' and command['command'] == ['docker', 'exec', source, 'ping', '-n', '-c', '2', '-W', '2',
            '-M', case['mode'], '-s', str(case['icmp_payload_bytes']), '-p', 'a1b2c3d4', evidence['destination']],
            'Probe differs from captured case')
        require(case['source_ip_bytes'] == case['icmp_payload_bytes'] + 28 and case['start_ns'] < case['end_ns'],
                'Probe size or interval differs')
        matching = [p for p in packets if case['start_ns'] <= p['monotonic_ns'] <= case['end_ns']]
        emitted = [p for p in matching if p['device'] == source and p['packet_type'] == 4]
        deltas = []
        before_rows = [by_id[x] for x in case.get('filters_before', [])]
        after_rows = [by_id[x] for x in case.get('filters_after', [])]
        require(len(before_rows) == len(after_rows), 'Incomplete filter counter interval')
        for before_row, after_row in zip(before_rows, after_rows):
            require(before_row['command'] == after_row['command'] and before_row['kind'] == 'filters-before' and
                    after_row['kind'] == 'filters-after', 'Filter counter observation identity differs')
            def counters(text):
                return {rule: (int(packets), int(size)) for packets, size, rule in
                        re.findall(r'^\[(\d+):(\d+)\] (-A .* -j DROP)$', text, re.M)}
            prior, later = counters(before_row['stdout']), counters(after_row['stdout'])
            require(prior.keys() == later.keys(), 'Drop rules changed during probe')
            for rule in prior:
                count, size = later[rule][0] - prior[rule][0], later[rule][1] - prior[rule][1]
                require(count >= 0 and size >= 0, 'Drop counters decreased during probe')
                if count:
                    deltas.append({'device': before_row['command'][2], 'rule': rule, 'packets': count, 'bytes': size,
                        'before': before_row['id'], 'after': after_row['id']})
        if command['returncode']:
            require(command['returncode'] == 1, 'Unexpected probe failure')
            if 'message too long, mtu=' in command['stderr']:
                require(not emitted, 'Local size rejection nevertheless emitted traffic')
                outcome = 'local_size_error'
            else:
                require('2 packets transmitted, 0 received' in command['stdout'] and emitted and deltas,
                        'No-reply probe lacks source packets and increased drop counters')
                outcome = 'no_reply_with_observed_drops'
        else:
            require('2 received, 0% packet loss' in command['stdout'] and emitted, 'Successful probe lacks actual traffic')
            outcome = 'successful_reply'
        cases.append(case | {'device': source, 'result': command['returncode'], 'outcome': outcome,
            'dropCounterChanges': deltas, 'stdout': command['stdout'],
            'stderr': command['stderr'], 'packetIds': [p['id'] for p in matching],
            'fragmentedPorts': sorted({p['device'] + ':' + p['interface'] for p in matching if p['mf'] or p['fragment_offset']})})
    used = {p['device'] for p in packets}
    report = {'devices': [devices[d] for d in sorted(used)], 'interfaces': interfaces, 'cases': cases,
        'packets': packets, 'configuration': configuration, 'manifestSha256': manifest_hash,
        'rawObservationIds': sorted(raw_ids), 'projectionVersion': 'native-packet-sizing-v1',
        'scope': [SCOPE, evidence['scope'], 'Source errors and packet sizes are observed outcomes, not a universal no-fragmentation guarantee.',
            'Ciphertext bytes are retained. Matching a probe interval alone does not prove the cryptographic plaintext/ciphertext relation.']}
    return manifest | {'runtime_backend': 'native-frr-ovs-strongswan-linux'}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    require(observation in report['rawObservationIds'], 'Observation is outside validated sizing capture')
    command = next(c for c in json.loads((Path(directory) / 'commands.json').read_text()) if c['id'] == observation)
    if command['kind'] == 'packet-observer' and not stderr:
        return (Path(directory) / command['output']).read_text()
    return command.get('stderr' if stderr else 'stdout', '')


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
