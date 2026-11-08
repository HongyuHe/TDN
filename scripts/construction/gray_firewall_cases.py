"""Construct nonempty Gray firewall protocol and cross-level test packets from recorded paths."""
import copy
import ipaddress
import json
from pathlib import Path
import struct

from outer_gray_cases import make_case
from boundary_application_cases import firewall_case
from boundary_transform_cases import checksum


def with_options(sample):
    result = copy.deepcopy(sample)
    result['header']['ipv4HeaderWords'] = 6
    result['bytes'] += 4
    result['header']['networkBytes'] = result['bytes']
    network = bytes(result['network']) + bytes([1, 1, 0, 0])
    network = bytes([70]) + network[1:2] + struct.pack('!H', result['bytes']) + network[4:10] + bytes([0, 0]) + network[12:]
    result['network'] = list(network[:10] + struct.pack('!H', checksum(network)) + network[12:])
    return result


def main():
    directory = Path('data/evidence/continuation')
    baseline = json.loads((directory / 'BoundaryBaseline.json').read_text())
    shared = json.loads((directory / 'GrayFirewallShared.json').read_text())
    records = shared['records']
    pair_index = next(index for index, row in enumerate(records['pairs'])
                      if row['endpoints']['source'] == 'V31F_I_B1' and row['endpoints']['destination'] == 'V31F_I_A1')
    pair = records['pairs'][pair_index]['endpoints']
    reply = make_case(records, 'V31F_GF_A:g1', pair_index, 500, 9999)
    ordinary = make_case(records, 'V31F_GF_A:g1', pair_index, 500, 500)
    esp = firewall_case(records, 'V31F_GF_A', 'g1', pair['sourceAddress'], pair['destinationAddress'], 'inbound')
    udp_esp = make_case(records, 'V31F_GF_A:g1', pair_index, 4500, 9999)
    udp_esp['payload'] = [1, 2, 3, 4, 0, 0, 0, 1]
    udp_esp['header']['payloadBytes'] = udp_esp['payload']
    udp_esp['bytes'] = 36
    udp_esp['header']['networkBytes'] = 36
    udp_esp['transport'] = list(struct.pack('!HHHH', 4500, 9999, 16, 0))
    network = bytes(udp_esp['network'])
    network = network[:2] + struct.pack('!H', 36) + network[4:10] + bytes([0, 0]) + network[12:]
    udp_esp['network'] = list(network[:10] + struct.pack('!H', checksum(network)) + network[12:])
    baseline_records = baseline['records']
    addresses = {row['id']: row['address'] for row in baseline_records['interfaces']}
    baseline_cross = firewall_case(baseline_records, 'V31B_GF_A', 's1',
                                   addresses['V31B_I_A1:gray'], addresses['V31B_I_A2:gray'], 'inbound')
    addresses = {row['id']: row['address'] for row in records['interfaces']}
    shared_cross = firewall_case(records, 'V31F_GF_A', 's1',
                                 addresses['V31F_I_A1:gray'], addresses['V31F_I_A2:gray'], 'inbound')
    malformed = copy.deepcopy(ordinary)
    malformed['payload'][17] = 16
    malformed['header']['payloadBytes'] = malformed['payload']
    baseline_devices = {row['id']: row for row in baseline_records['components']}
    shared_devices = {row['id']: row for row in records['components']}
    result = dict(baselineCrossSource=baseline_devices['V31B_I_A1'],
                  baselineCrossDestination=baseline_devices['V31B_I_A2'],
                  sharedCrossSource=shared_devices['V31F_I_A1'],
                  sharedCrossDestination=shared_devices['V31F_I_A2'],
                  reply=reply, ordinaryIKE=ordinary, replyWithOptions=with_options(reply), esp=esp,
                  udpESP=udp_esp, malformedIKE=malformed, baselineCross=baseline_cross, sharedCross=shared_cross,
                  provenance=dict(shared=shared['provenance'], baseline=baseline['provenance'],
                                  fixtureScope='Constructed protocol-class packets on recorded native paths; no usable IKE exchange or authentication is inferred from framing.'))
    (directory / 'GrayFirewallCases.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    raw = shared['native']['rawBundle']
    by_id = {row['id']: row for row in raw['sourceInterfaces']}
    if set(by_id) != {row['id'] for row in records['interfaces']}:
        raise ValueError('Every raw interface must remain in the projection')
    raw_interfaces = []
    for row in records['interfaces']:
        addresses = [item for item in by_id[row['id']]['addresses'] if item['family'] == 'inet']
        if len(addresses) > 1:
            raise ValueError('Multiple IPv4 addresses need explicit expansion')
        raw_interfaces.append({**row, 'address': int(ipaddress.ip_address(addresses[0]['local'])) if addresses else None})
    (directory / 'GrayFirewallSharedProjection.json').write_text(json.dumps(dict(rawInterfaces=raw_interfaces), indent=2, sort_keys=True) + '\n')
    print(json.dumps({name: dict(ingress=value['entryIface'], egress=value['route']['egress'])
                      for name, value in result.items() if isinstance(value, dict) and 'entryIface' in value}))


if __name__ == '__main__':
    main()
