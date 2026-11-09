"""Derive a recorded Inner-to-Outer forwarding path without changing captured inventories."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from packet_sizing_cases import selected_route


def outer_header(policy):
    return dict(source=policy['sender'], destination=policy['receiver'], protocol='esp', ingress='', egress='',
                sourcePort=0, destinationPort=0, ipv4HeaderWords=5, ipv6NextHeader=0,
                matchedInboundPolicyIds=[], matchedOutboundPolicyIds=[], connectionState='', hopLimit=64, icmpType=0, icmpCode=0, etherType=None, payloadBytes=None, connectionId=None,
                networkBytes=None, ipv4FragmentOffset=None)


def matching_policies(device, header):
    return [row for row in device['egressPolicies']
            if row['sourceLow'] <= header['source'] <= row['sourceHigh'] and
            row['destinationLow'] <= header['destination'] <= row['destinationHigh']]


def build(source, cases, destination):
    saved = json.loads(source.read_text())
    sample = json.loads(cases.read_text())['path']
    records = saved['records']
    moves = []
    port = sample['routeOuterPacket']['egress']
    phase = 'ready'
    header = outer_header(sample['policy'])
    encrypted_outer = False

    def add(operation, **fields):
        move = dict(operation=operation, header=copy.deepcopy(header), next=port, route=sample['route'],
                    policy=sample['policy'], association=sample['association'])
        move.update(fields)
        moves.append(move)

    def neighbors(first):
        return [last for current, last in records['links'] if first == current]

    def outer_peer(first):
        owner = records['nativeIfaces'][first]['owner']
        return bool(matching_policies(records['nativeDevices'][owner], header))

    for _ in range(30):
        if encrypted_outer and phase == 'ready':
            break
        if phase == 'ready':
            next_ports = neighbors(port)
            if len(next_ports) != 1:
                raise ValueError('The chosen recorded path lacks one physical next port')
            add('linkTransmit', next=next_ports[0])
            port = next_ports[0]
            phase = 'received'
            continue
        if phase != 'received':
            raise ValueError('Unexpected path phase')
        bridge = [last for first, last in records['bridges'] if first == port]
        if bridge:
            choices = [last for last in bridge if any(outer_peer(next_port) for next_port in neighbors(last))]
            if len(choices) != 1:
                raise ValueError('The chosen bridge lacks one Outer-bound possible destination')
            add('bridge', next=choices[0])
            port = choices[0]
            phase = 'ready'
            continue
        add('receive')
        route = selected_route(records, port, header['destination'])
        add('route', route=route)
        port = route['egress']
        header['hopLimit'] -= 1
        add('forwardFilter')
        owner = records['nativeIfaces'][port]['owner']
        candidates = matching_policies(records['nativeDevices'][owner], header)
        if candidates:
            policy = min(candidates, key=lambda row: row['priority'])
            states = [row['installation']['association'] for row in saved['installations']
                      if row['installation']['device'] == owner and row['installation']['direction'] == 'outbound'
                      and row['installation']['association']['reqid'] == policy['id']
                      and row['installation']['association']['sender'] == policy['sender']
                      and row['installation']['association']['receiver'] == policy['receiver']]
            if len(states) != 1:
                raise ValueError('The Outer path lacks one bound outbound state')
            add('encryptIPsec', policy=policy, association=states[0])
            header = outer_header(policy)
            outer_route = selected_route(records, port, header['destination'])
            add('route', route=outer_route)
            port = outer_route['egress']
            encrypted_outer = True
        else:
            add('forwardWithoutEncap')
        phase = 'ready'
    else:
        raise ValueError('The recorded continuation did not reach Outer output')
    selected = [role for role in saved['sizingRoles'] if role['iface'] == port]
    if len(selected) != 1 or selected[0]['role'] != 'grayFirewallOrEncryptionExternal':
        raise ValueError('The final interface is not a mandatory sizing interface')
    next_ports = neighbors(port)
    if len(next_ports) != 1:
        raise ValueError('The mandatory interface lacks one wire neighbor')
    transmission = dict(operation='linkTransmit', header=header, next=next_ports[0], route=sample['route'],
                        policy=sample['policy'], association=sample['association'])
    result = dict(moves=moves, transmission=transmission, endpoint=selected[0]['interface'], endpointPort=port,
                  sourceSHA256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  casesSHA256=hashlib.sha256(cases.read_bytes()).hexdigest(),
                  scope='Possible native forwarding path through recorded NORMAL destinations and exact IP rules. No guaranteed OVS delivery claim.')
    destination.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('cases', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    result = build(args.source, args.cases, args.destination)
    print(json.dumps(dict(steps=len(result['moves']), endpoint=result['endpoint'])))


if __name__ == '__main__':
    main()
