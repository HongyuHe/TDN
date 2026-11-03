"""Expose byte-derived lengths and guard outcomes from the mixed sizing experiment."""
import hashlib
import json
from pathlib import Path
import re

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require
from .sizing import packet_fields

CAPABILITIES = ['devices', 'cases', 'packets', 'configuration', 'observations', 'coverage']
LEAN_VIEW = 'mixed_packet_sizing'
SCOPE = 'MACsec, standalone L2TPv3 and outer ESP boundary observations'
SIZES = [1228, 1359, 1360, 1361, 1414, 1415, 1468, 1469, 1500, 1501, 4028]
PHASES = ['before', 'outer-guard', 'inner-and-outer-guard']
COLLECTOR_HASH = '464baceb3661712516b8e122072aee409e2d225148cb6aea944196603249f996'


def frame_fields(raw):
    require(len(raw) >= 14, 'Truncated Ethernet observation')
    ether_type = int.from_bytes(raw[12:14], 'big')
    result = {'etherType': ether_type, 'frame_bytes': len(raw),
              'sha256': hashlib.sha256(raw).hexdigest()}
    if ether_type == 0x0800:
        result.update(packet_fields(raw))
        header = result['ip_header_bytes']
        payload = raw[14 + header:14 + result['ip_bytes']]
        if result['fragment_offset'] == 0 and result['protocol'] == 17 and len(payload) >= 8:
            result['udp'] = {'sourcePort': int.from_bytes(payload[:2], 'big'),
                'destinationPort': int.from_bytes(payload[2:4], 'big'),
                'length': int.from_bytes(payload[4:6], 'big'), 'payloadHex': payload[8:].hex()}
        if result['fragment_offset'] == 0 and result['protocol'] == 50 and len(payload) >= 8:
            result['esp'] = {'spi': int.from_bytes(payload[:4], 'big'),
                             'sequence': int.from_bytes(payload[4:8], 'big')}
    elif ether_type == 0x88e5:
        require(len(raw) >= 20, 'Truncated MACsec header')
        sci_present = bool(raw[14] & 0x20)
        tag_bytes = 14 if sci_present else 6
        require(len(raw) >= 14 + tag_bytes, 'Truncated MACsec SCI')
        result['macsec'] = {'tciAn': raw[14], 'shortLength': raw[15],
            'packetNumber': int.from_bytes(raw[16:20], 'big'),
            'sciPresent': sci_present, 'secTagBytes': tag_bytes,
            'sci': raw[20:28].hex() if sci_present else None,
            'bytesAfterSecTag': len(raw) - 14 - tag_bytes}
    else:
        raise ValueError('Unsupported sizing EtherType')
    return result


def drop_counters(text):
    return {rule: (int(packets), int(size)) for packets, size, rule in
            re.findall(r'^\[(\d+):(\d+)\] (-A .* -j DROP)$', text, re.M)}


def parse(directory):
    root = Path(directory)
    digest = validate_files(root)
    require(hashlib.sha256((root / 'mixed-sizing.source.py').read_bytes()).hexdigest() == COLLECTOR_HASH,
            'Unreviewed mixed sizing collector')
    evidence = json.loads((root / 'evidence.json').read_text())
    sizing = json.loads((root / 'sizing.json').read_text())
    commands = json.loads((root / 'commands.json').read_text())
    require(evidence['error'] is None, 'Mixed sizing collection failed')
    require(sizing['schema'] == 'mixed-packet-sizing/v1' and sizing['sizes'] == SIZES,
            'Unsupported mixed sizing case inventory')
    by_id = {row['id']: row for row in commands}
    require(len(by_id) == len(commands), 'Duplicate mixed sizing command')
    devices = {row['id']: row for row in evidence['devices']}
    packets = []
    observers = sizing['observers']
    expected_ports = {(node + site, port) for site in ['A', 'B'] for node, port in [
        ('H', 'red'), ('I', 'red'), ('I', 'macsec0'), ('I', 'gray'), ('E', 'innerframes'),
        ('E', 'l2tpeth0'), ('E', 'uplink'), ('O', 'gray'), ('O', 'black'), ('F', 'outside')]}
    expected_observers = {(phase, device, port) for phase in PHASES for device, port in expected_ports}
    require(len(observers) == len(expected_observers) and
            {(r['phase'], r['device'], r['interface']) for r in observers} == expected_observers,
            'Incomplete or duplicate mixed packet observers')
    for index, observer in enumerate(observers):
        require(observer['device'] in devices and observer['returncode'] in [0, -15] and
                observer['stderr'] == '' and observer['stopped_by_collector'], 'Mixed packet observer failed')
        path = root / observer['file']
        path.resolve().relative_to(root.resolve())
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        require(rows and rows[0].get('ready') and rows[0]['interface'] == observer['interface'],
                'Mixed packet observer was not ready')
        require(all(a['monotonic_ns'] <= b['monotonic_ns'] for a, b in zip(rows, rows[1:])),
                'Mixed packet observation order differs')
        for number, row in enumerate(rows[1:]):
            require(row['interface'] == observer['interface'] and row['packet_type'] in [0, 1, 2, 3, 4],
                    'Mixed packet interface or direction differs')
            parsed = frame_fields(bytes.fromhex(row['frame_hex']))
            require(row['frame_bytes'] == parsed['frame_bytes'] and row['sha256'] == parsed['sha256'],
                    'Captured frame metadata differs from bytes')
            packets.append(row | parsed | {'id': 'mixed-frame-%d-%d' % (index, number),
                'device': observer['device'], 'phase': observer['phase'], 'capture': observer['file']})
    expected_cases = {(phase, source, mode, size) for phase in PHASES for source in ['HA', 'HB']
                      for mode in ['do', 'dont'] for size in SIZES}
    require(len(sizing['cases']) == len(expected_cases) and
            {(r['phase'], r['source'], r['mode'], r['source_ip_bytes']) for r in sizing['cases']} == expected_cases,
            'Incomplete or duplicate mixed sizing cases')
    cases = []
    for case in sizing['cases']:
        command = by_id[case['observation']]
        destination = '10.2.0.2' if case['source'] == 'HA' else '10.1.0.2'
        require(case['destination'] == destination and command['device_id'] == case['source'] and
            command['command'] == ['ip', 'netns', 'exec', 'tdnv31p-' + case['source'], 'ping', '-n',
                '-c', '1', '-W', '1', '-M', case['mode'], '-s', str(case['source_ip_bytes'] - 28),
                '-p', 'a1b2c3d4', destination] and command['returncode'] == case['returncode'],
            'Mixed probe differs from its command')
        require(case['start_ns'] < case['end_ns'], 'Invalid mixed probe interval')
        matching = [p['id'] for p in packets if p['phase'] == case['phase'] and
                    case['start_ns'] <= p['monotonic_ns'] <= case['end_ns']]
        deltas = []
        require(len(case['filters_before']) == len(case['filters_after']) == 6,
                'Incomplete mixed filter counters')
        for before_id, after_id in zip(case['filters_before'], case['filters_after']):
            before, after = by_id[before_id], by_id[after_id]
            require(before['command'] == after['command'] and before['returncode'] == after['returncode'] == 0
                    and before['command'][-2:] == ['iptables-save', '-c'], 'Mixed counter identity differs')
            first, last = drop_counters(before['stdout']), drop_counters(after['stdout'])
            require(first.keys() == last.keys(), 'Rules changed during a mixed probe')
            for rule, (count, size) in last.items():
                prior_count, prior_size = first[rule]
                require(count >= prior_count and size >= prior_size, 'Mixed counters decreased')
                if count != prior_count or size != prior_size:
                    deltas.append({'device': before['device_id'], 'rule': rule,
                        'packets': count - prior_count, 'bytes': size - prior_size,
                        'before': before_id, 'after': after_id})
        cases.append(case | {'device': case['source'], 'packetObservations': matching, 'dropCounterChanges': deltas,
            'stdout': command['stdout'], 'stderr': command['stderr']})
    report = {'devices': list(devices.values()), 'cases': cases, 'packets': packets,
        'configuration': [r for r in commands if r['command'][4:6] != ['ping', '-n']],
        'observations': [{'id': r['id'], 'record': r} for r in commands],
        'rawObservationIds': list(by_id), 'manifestSha256': digest,
        'projectionVersion': 'mixed-packet-sizing-v1', 'probes': evidence['probes'],
        'coverage': [{'cases': len(cases), 'observers': len(observers), 'phases': PHASES}],
        'scope': [SCOPE, sizing['scope'],
            'Time-window grouping associates observations with probes; it does not prove ciphertext/plaintext equality.',
            'The public MACsec header reports SCI presence and length; ICV and ESP transform lengths require the captured configuration.']}
    return {'runtime_backend': evidence['runtime_backend']}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    rows = [r for r in report['observations'] if r['id'] == observation]
    require(len(rows) == 1, 'Unknown mixed sizing observation')
    return rows[0]['record']['stderr' if stderr else 'stdout']


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
