"""Build source-linked native filter, protection and wire-step examples."""
import argparse
import ipaddress
import json
from pathlib import Path
import struct


def checksum(data):
    if len(data) % 2:
        data += bytes([0])
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def route(records, ingress, destination):
    choices = [r for r in records['routes'] if r['ingress'] == ingress and
               r['low'] <= destination <= r['high']]
    return min(choices, key=lambda r: (r['tablePriority'], -r['prefixLength'], r['metric']))


def case(records, prefix, kind, level, service_port=8080):
    if kind == 'inner':
        owner = prefix + '_I_A' + str(level)
        target = prefix + '_R_B' + str(level) + ':red'
        source = next(i['address'] for i in records['interfaces'] if i['id'] == prefix + '_R_A' + str(level) + ':red')
        destination = next(i['address'] for i in records['interfaces'] if i['id'] == target)
        entry_name, exit_name, protocol = 'red', 'gray', 'tcp'
        source_port, destination_port = 40000, service_port
        payload = []
        transport = struct.pack('!HHIIBBHHH', source_port, destination_port, 1, 0, 80, 2, 65535, 0, 0)
        pseudo = struct.pack('!IIBBH', source, destination, 0, 6, len(transport))
        transport = transport[:16] + struct.pack('!H', checksum(pseudo + transport)) + transport[18:]
    else:
        owner = prefix + '_O_A1'
        pair = next(p['endpoints'] for p in records['pairs'] if p['endpoints']['source'] == prefix + '_I_A' + str(level) and
                    p['endpoints']['destination'] == prefix + '_I_B' + str(level))
        source, destination = pair['sourceAddress'], pair['destinationAddress']
        entry_name, exit_name, protocol = ('gray' if prefix == 'V31B' else 'gray' + str(level)), 'black', 'esp'
        source_port, destination_port = 0, 0
        payload = [1, 2, 3, 4, 0, 0, 0, 1]
        transport = bytes()
    entry = records['ifaceNames'].index(owner + ':' + entry_name)
    chosen = route(records, entry, destination)
    out = chosen['egress']
    if records['ifaceNames'][out] != owner + ':' + exit_name:
        raise ValueError('The selected route changed the expected boundary port')
    device = records['nativeDevices'][records['nativeIfaces'][out]['owner']]
    policies = [p for p in device['outbound'] if p['sourceLow'] <= source <= p['sourceHigh'] and
                p['destinationLow'] <= destination <= p['destinationHigh']]
    policy = min(policies, key=lambda p: p['priority'])
    associations = [s for s in device['states'] if s['localRequestId'] == policy['id'] and
                    s['sender'] == policy['sender'] and s['receiver'] == policy['receiver'] and
                    (policy['templateSPI'] is None or s['wireIdentity'] == policy['templateSPI'])]
    if len(associations) != 1:
        raise ValueError('Expected one installed bound outbound SA')
    association = associations[0]
    outer_route = route(records, out, policy['receiver'])
    wire = next(next_port for port, next_port in records['links'] if port == outer_route['egress'])
    length = 20 + len(transport) + len(payload)
    header = {'source': source, 'destination': destination, 'protocol': protocol, 'ingress': '', 'egress': '',
              'sourcePort': source_port, 'destinationPort': destination_port, 'ipv4HeaderWords': 5,
              'inboundPolicies': [], 'outboundPolicies': [], 'connectionState': 'new',
              'hopLimit': 64, 'payloadBytes': payload if protocol == 'tcp' else None,
              'networkBytes': length, 'ipv4FragmentOffset': 0 if protocol == 'tcp' else None,
              'ipv6NextHeader': 0, 'icmpType': 0, 'icmpCode': 0, 'etherType': None, 'connectionId': None}
    protocol_id = 6 if protocol == 'tcp' else 50
    network = struct.pack('!BBHHHBBHII', 69, 0, length, 0, 0, 63, protocol_id, 0, source, destination)
    network = network[:10] + struct.pack('!H', checksum(network)) + network[12:]
    forward = {'interface': records['interfaces'][out], 'entryIface': entry, 'route': chosen,
               'header': header, 'network': list(network), 'transport': list(transport), 'payload': payload,
               'entryMtu': records['interfaces'][entry]['mtu'], 'exitMtu': records['interfaces'][out]['mtu'],
               'bytes': length}
    return {'forward': forward, 'policy': policy, 'association': association, 'routeOuterPacket': outer_route, 'wirePort': wire}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--registered', action='store_true')
    args = parser.parse_args()
    source = 'Boundary' if args.registered else 'OuterGray'
    output = 'BoundaryRegisteredTransform' if args.registered else 'BoundaryTransform'
    for profile, prefix, level in [('Baseline', 'V31B', 1), ('Shared', 'V31F', 2)]:
        records = json.loads(Path('data/evidence/continuation/' + source + profile + 'Fields.json').read_text())
        result = {kind: case(records, prefix, kind, level) for kind in ['inner', 'outer']}
        path = Path('data/evidence/continuation/' + output + profile + '.json')
        path.write_text(json.dumps(result, indent=2) + '\n')
        print(str(path))


if __name__ == '__main__':
    main()
