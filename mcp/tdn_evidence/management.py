"""Preserve observed management initiators, replies, and rejected attempts."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ['devices', 'interfaces', 'sessions', 'packets', 'conntrack', 'probes']
LEAN_VIEW = 'management_sessions'
SCOPE = 'One captured AW-initiated HTTPS exchange, with raw TCP identity and explicit negative attempts'


def tcp_packet(raw):
    require(len(raw) >= 40 and raw[0] >> 4 == 4 and raw[9] == 6, 'Expected IPv4 TCP packet')
    ihl = (raw[0] & 15) * 4
    total = int.from_bytes(raw[2:4], 'big')
    require(20 <= ihl <= total <= len(raw) and int.from_bytes(raw[6:8], 'big') & 0x3fff == 0,
            'Unsupported fragmented or truncated packet')
    tcp = raw[ihl:total]
    require(len(tcp) >= 20 and 20 <= (tcp[12] >> 4) * 4 <= len(tcp), 'Invalid TCP header length')
    return {'source': str(ipaddress.IPv4Address(raw[12:16])),
        'destination': str(ipaddress.IPv4Address(raw[16:20])),
        'sourcePort': int.from_bytes(tcp[:2], 'big'), 'destinationPort': int.from_bytes(tcp[2:4], 'big'),
        'protocol': 'tcp', 'sequence': int.from_bytes(tcp[4:8], 'big'),
        'acknowledgment': int.from_bytes(tcp[8:12], 'big'), 'flags': tcp[13],
        'payloadBytes': len(tcp) - (tcp[12] >> 4) * 4,
        'tcpPayloadHex': tcp[(tcp[12] >> 4) * 4:].hex(),
        'ipPacketHex': raw[:total].hex(), 'packetSha256': hashlib.sha256(raw[:total]).hexdigest()}


def tuple_of(packet):
    return tuple(packet[k] for k in ['source', 'destination', 'sourcePort', 'destinationPort', 'protocol'])


def reversed_tuple(value):
    return value[1], value[0], value[3], value[2], value[4]


def parse(directory):
    directory = Path(directory)
    manifest_hash = validate_files(directory)
    manifest = json.loads((directory / 'manifest.json').read_text())
    evidence = json.loads((directory / 'evidence.json').read_text())
    commands = json.loads((directory / 'commands.json').read_text())
    require(manifest['schema'] == evidence['schema'] == 'management-session/v1', 'Unknown management schema')
    require(manifest['error'] is None and evidence['error'] is None, 'Failed management capture')
    require(manifest['configuration_id'] == evidence['configuration_id'], 'Management capture identity differs')
    devices = {d['id']: d for d in evidence['devices']}
    require(set(devices) == {'AW', 'OUTER'} and len(evidence['devices']) == 2, 'Unexpected device inventory')
    by_id = {c['id']: c for c in commands}
    require(len(by_id) == len(commands), 'Duplicate command ID')
    raw_ids = set()
    phases = {}
    for name in ['established', 'before-negative', 'after-unsolicited', 'after-unbound-reply']:
        phase = json.loads((directory / (name + '.json')).read_text())
        require(set(phase) == set(devices), 'Incomplete session phase')
        for device, observations in phase.items():
            for kind, row in observations.items():
                require(by_id.get(row['id']) == row and row['device'] == device and row['returncode'] == 0,
                        'Unbound or failed session observation')
                expected = {'interfaces': ['ip', '-j', '-d', 'addr'], 'routes': ['ip', '-j', 'route'],
                    'filters': ['iptables-save', '-c'], 'conntrack': ['conntrack', '-L', '-p', 'tcp', '-o', 'extended']}
                require(kind in expected and row['command'] ==
                    ['ip', 'netns', 'exec', devices[device]['namespace'], *expected[kind]],
                    'Session observation command differs')
                raw_ids.add(row['id'])
        phases[name] = phase
    interfaces, ownership = [], {}
    for device in devices:
        observed = phases['established'][device]['interfaces']
        ports = [p for p in json.loads(observed['stdout']) if p['ifname'] == 'gray']
        require(len(ports) == 1, 'Missing management interface')
        port = ports[0]
        addresses = [a['local'] for a in port['addr_info'] if a['family'] == 'inet']
        require(len(addresses) == 1 and addresses[0] not in ownership, 'Ambiguous interface address')
        ownership[addresses[0]] = device
        interfaces.append({'device': device, 'name': 'gray', 'ifindex': port['ifindex'],
            'mac': port['address'], 'addresses': addresses, 'observation': observed['id']})

    def log(name):
        matches = [c for c in commands if c['command'][0] == 'cat' and
                   Path(c['command'][-1]).name == name + '.jsonl']
        require(len(matches) == 1 and matches[0]['returncode'] == 0, 'Missing or failed log observation')
        record = matches[0]
        require(record['stdout'] == (directory / (name + '.jsonl')).read_text(), 'Log differs from command output')
        raw_ids.add(record['id'])
        return record, [json.loads(line) for line in record['stdout'].splitlines()]

    packets = []
    for device in devices:
        observation, rows = log('capture-' + device)
        rows = [row for row in rows if 'frame_hex' in row]
        require(all(a['monotonic_ns'] <= b['monotonic_ns'] for a, b in zip(rows, rows[1:])),
                'Packet observations are not ordered')
        for index, row in enumerate(rows):
            require(row['interface'] == 'gray' and row['packet_type'] in [0, 4], 'Unsupported observed interface/type')
            frame = bytes.fromhex(row['frame_hex'])
            require(frame[12:14] == bytes.fromhex('0800'), 'EtherType differs')
            packet = tcp_packet(frame[14:])
            direction = 'outbound' if row['packet_type'] == 4 else 'inbound'
            require(ownership.get(packet['source' if direction == 'outbound' else 'destination']) == device,
                    'Packet interface ownership differs')
            packets.append(packet | {'id': observation['id'] + ':' + str(index), 'device': device,
                'interface': 'gray', 'direction': direction, 'monotonicNs': row['monotonic_ns'],
                'observation': observation['id'], 'frameHex': row['frame_hex'], 'etherType': 2048})
    aw = [p for p in packets if p['device'] == 'AW']
    requests = [p for p in aw if p['direction'] == 'outbound' and p['flags'] & 0x12 == 2]
    require(len(requests) == 1, 'Expected one AW connection request')
    request = requests[0]
    original = tuple_of(request)
    require(ownership[original[0]] == 'AW' and ownership[original[1]] == 'OUTER' and original[3] == 443,
            'Original management tuple differs')
    replies = [p for p in aw if tuple_of(p) == reversed_tuple(original)]
    require(bool(replies) and all(request['monotonicNs'] < p['monotonicNs'] for p in replies),
            'Reply has no preceding connection request')
    syn_ack = next((p for p in replies if p['flags'] & 0x12 == 0x12), None)
    require(syn_ack is not None and syn_ack['acknowledgment'] == (request['sequence'] + 1) % 2**32,
            'Reply does not acknowledge original request')
    require(any(p['payloadBytes'] > 0 for p in replies), 'No returned session data')
    for packet in aw:
        require(tuple_of(packet) in [original, reversed_tuple(original)], 'Unexpected packet on AW wire')
        require(any(other['device'] == 'OUTER' and other['direction'] != packet['direction'] and
                    other['packetSha256'] == packet['packetSha256'] for other in packets),
                'Packet lacks matching peer capture')
    conntracks = []
    pattern = re.compile(r'tcp\s+6\s+\d+\s+(\w+)\s+src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+) src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)')
    for device in devices:
        observed = phases['established'][device]['conntrack']
        matches = list(pattern.finditer(observed['stdout']))
        require(len(matches) == 1, 'Expected one captured TCP connection')
        state, src, dst, sport, dport, rsrc, rdst, rsport, rdport = matches[0].groups()
        require(state == 'ESTABLISHED' and (src, dst, int(sport), int(dport), 'tcp') == original and
                (rsrc, rdst, int(rsport), int(rdport), 'tcp') == reversed_tuple(original),
                'Conntrack original/reply tuple differs')
        conntracks.append({'device': device, 'state': state, 'originalTuple': list(original),
            'replyTuple': list(reversed_tuple(original)), 'observation': observed['id'],
            'startNs': observed['start_ns'], 'endNs': observed['end_ns'], 'raw': observed['stdout']})
    application = {}
    for name in ['client', 'server']:
        observation, rows = log(name)
        events = [row for row in rows if 'event' in row]
        require([row['event'] for row in events] == ['request', 'response'], 'Incomplete application exchange')
        application[name] = {'observation': observation['id'], 'events': events}
    require(application['client']['events'][0]['bytes_hex'] == application['server']['events'][0]['bytes_hex'] and
            application['client']['events'][1]['bytes_hex'] == application['server']['events'][1]['bytes_hex'],
            'HTTPS application records differ')
    for endpoint, peer, local in [('client', original[1:2] + (original[3],), original[0:1] + (original[2],)),
                                  ('server', original[0:1] + (original[2],), original[1:2] + (original[3],))]:
        sent, received = application[endpoint]['events']
        require(sent['peer'] == list(peer) and sent['local'] == list(local) and
                sent['monotonic_ns'] < received['monotonic_ns'], 'Application tuple/order differs')

    def drops(name):
        raw = phases[name]['OUTER']['filters']['stdout']
        found = re.findall(r'^\[(\d+):\d+\] -A OUTPUT -j DROP$', raw, re.M)
        require(len(found) == 1, 'Missing explicit output-drop counter')
        return int(found[0])

    probes = []
    for event, before, after in [('unsolicited_connect', 'before-negative', 'after-unsolicited'),
                                ('unbound_reply_attempt', 'after-unsolicited', 'after-unbound-reply')]:
        matches = []
        for command in commands:
            if command.get('device') != 'OUTER' or command.get('returncode') != 0:
                continue
            try:
                value = json.loads(command.get('stdout', ''))
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and value.get('event') == event:
                matches.append((command, value))
        require(len(matches) == 1, 'Missing negative session attempt')
        command, value = matches[0]
        require(command['command'][:6] == ['ip', 'netns', 'exec', devices['OUTER']['namespace'], 'python3', '-c'],
                'Negative attempt is not bound to Outer namespace')
        require(drops(after) > drops(before), 'Negative attempt did not increase output drops')
        if event == 'unsolicited_connect':
            require(value['result'] != 0 and ownership.get(value['source']) == 'OUTER' and
                    ownership.get(value['destination']) == 'AW', 'Unexpected initiation outcome')
        else:
            raw = bytes.fromhex(value['packet_hex'])
            attempted = tcp_packet(raw)
            require(hashlib.sha256(raw).hexdigest() == value['sha256'] and tuple_of(attempted) != reversed_tuple(original),
                    'Unbound-reply identity differs or belongs to allowed connection')
            require(not any(p['packetSha256'] == attempted['packetSha256'] for p in packets),
                    'Rejected reply appeared on captured wire')
        raw_ids.add(command['id'])
        probes.append({'device': 'OUTER', 'kind': event, 'observed': value, 'observation': command['id'],
            'dropBefore': drops(before), 'dropAfter': drops(after), 'before': before, 'after': after})
    session = {'id': hashlib.sha256((manifest_hash + request['packetSha256']).encode()).hexdigest(),
        'device': 'OUTER', 'initiator': 'AW', 'responder': 'OUTER', 'initiatorInterface': 'gray',
        'responderInterface': 'gray', 'originalTuple': list(original), 'request': request,
        'replies': replies, 'packetIds': [p['id'] for p in aw], 'application': application,
        'identitySource': 'Manifest hash and initial SYN packet hash; no numeric kernel connection ID was captured.',
        'ordering': 'Single AW capture uses CLOCK_MONOTONIC; peer records independently bind the packet bytes.'}
    report = {'devices': list(devices.values()), 'interfaces': interfaces, 'sessions': [session],
        'packets': packets, 'conntrack': conntracks, 'probes': probes, 'manifestSha256': manifest_hash,
        'rawObservationIds': sorted(raw_ids), 'projectionVersion': 'management-session-v1',
        'scope': [SCOPE, 'Packet bytes identify observed TCP segments; session direction comes from the SYN and original conntrack tuple.',
            'The parser checks observed correspondence. Linux TCP/TLS and collector behavior remain implementation assumptions.',
            'The experiment establishes no administrator identity, complete management-interface audit, or arbitrary future-session behavior.']}
    return manifest | {'runtime_backend': evidence['runtime_backend']}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    require(observation in report['rawObservationIds'], 'Observation is outside the validated session capture')
    rows = json.loads((Path(directory) / 'commands.json').read_text())
    row = next(row for row in rows if row['id'] == observation)
    return row.get('stderr' if stderr else 'stdout', '')


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
