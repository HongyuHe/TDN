import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path


def build_profiles(source):
    peers = source['parameters']
    if len(peers) != 2:
        raise ValueError('Two observed MKA peers are required')
    for peer in peers:
        required = {'controlledPortEnabled': True, 'protectFrames': True,
                    'encryptFrames': True, 'confidentialityOffset': 0,
                    'configuredMacsecPolicy': 1, 'configuredIntegrityOnly': 0,
                    'replayWindow': 2}
        if any(peer.get(key) != value for key, value in required.items()):
            raise ValueError('The captured peers do not supply the selected secure profile')
    names = [peer['device'] for peer in peers]
    addresses = [int.from_bytes(bytes([10, 91, 0, 1]), 'big'),
                 int.from_bytes(bytes([10, 91, 0, 2]), 'big')]
    associations = [{'tag': 1, 'sci': int(peer['sci'], 16),
                     'associationNumber': peer['transmitAssociationNumber'],
                     'keyGeneration': index + 1} for index, peer in enumerate(peers)]
    level = {'classification': 'model-test', 'compartments': [],
             'dissemination': [], 'otherControls': []}
    frames = []
    for index, association in enumerate(associations):
        src = association['sci'] // 65536
        dst = associations[1 - index]['sci'] // 65536
        frames.append([association, {'header': {'source': src, 'destination': dst,
                       'etherType': 35045, 'vlanTags': []},
                       'headerBytes': list(dst.to_bytes(6, 'big') + src.to_bytes(6, 'big') + b'\x88\xe5'),
                       'payload': [44 + association['associationNumber']] + [0] * 5 +
                                  list(association['sci'].to_bytes(8, 'big')) + [0] * 16}])
    result = {}
    for variant in ['direct', 'routed']:
        if variant == 'direct':
            owner_names = names
            iface_specs = [(0, 'macsec0', 'red', addresses[0], False),
                           (0, 'eth0', 'gray', None, True),
                           (1, 'macsec0', 'red', addresses[1], False),
                           (1, 'eth0', 'gray', None, True)]
            sources, logicals, physicals = [0, 2], [0, 2], [1, 3]
            links = [[1, 3], [3, 1]]
        else:
            owner_names = names + ['model-red-router']
            iface_specs = [(0, 'red', 'red', addresses[0], True),
                           (0, 'macsec0', 'gray', None, False),
                           (0, 'eth0', 'gray', None, True),
                           (1, 'red', 'red', addresses[1], True),
                           (1, 'macsec0', 'gray', None, False),
                           (1, 'eth0', 'gray', None, True),
                           (2, 'red', 'red', None, True)]
            sources, logicals, physicals = [0, 3], [1, 4], [2, 5]
            links = [[2, 5], [5, 2], [6, 0], [0, 6]]
        native_devices = []
        for index, name in enumerate(owner_names):
            native_devices.append({'forwardRules': [], 'inputRules': [], 'outputRules': [],
                'forwardFallback': 'allow', 'inputFallback': 'allow', 'outputFallback': 'allow',
                'egressPolicies': [], 'ingressPolicies': [], 'states': [],
                'localAddresses': [addresses[index]] if index < 2 else [],
                'ifaceSecurityDomain': index if index < 2 else None})
        native_ifaces = []
        interfaces = []
        for index, (owner, short_name, zone, address, physical) in enumerate(iface_specs):
            name = owner_names[owner] + ':' + short_name
            link_address = associations[owner]['sci'] // 65536 if owner < 2 else 2
            interfaces.append({'id': name, 'device': owner_names[owner], 'zone': zone,
                'address': address, 'namespaceAddresses': [], 'linkAddress': link_address,
                'physical': physical, 'externalData': index in physicals,
                'managementNetwork': False, 'mtu': 1500})
            native_ifaces.append({'owner': owner, 'name': name,
                'stack': [1] if index in physicals else [],
                'canOriginateTraffic': index in sources})
        mac_ifaces = []
        endpoints = []
        tunnels = []
        routes = []
        for index, peer in enumerate(peers):
            mac_ifaces.append({'logicalIface': logicals[index], 'physicalIface': physicals[index],
                'settings': {key: peer[key] for key in ['controlledPortEnabled', 'protectFrames',
                             'encryptFrames', 'confidentialityOffset']},
                'transmitAssociation': associations[index],
                'receiveAssociations': [associations[1-index]], 'validateStrict': True})
            tunnel = names[index] + '-to-' + names[1-index]
            endpoints.append({'sourceIface': physicals[index], 'destinationIface': physicals[1-index],
                'actorSCI': associations[index]['sci'], 'tunnel': tunnel})
            tunnels.append({'id': tunnel, 'layer': 'inner', 'mechanism': 'macsec',
                'sender': names[index], 'receiver': names[1-index],
                'keyContext': 'model-key-' + str(index + 1),
                'espTunnelMode': False, 'associatedIPTunnel': False})
            routes.append({'ingress': sources[index], 'egress': logicals[index],
                'destPrefixLow': 0, 'destPrefixHigh': 2**129, 'prefixLength': 0,
                'metric': 0, 'tablePriority': 32766})
            if logicals[index] != sources[index]:
                routes.append({'ingress': logicals[index], 'egress': sources[index],
                    'destPrefixLow': 0, 'destPrefixHigh': 2**129, 'prefixLength': 0,
                    'metric': 0, 'tablePriority': 32766})
        devices = [{'id': name, 'site': 'site-' + str(index),
                    'kind': 'macsec' if index < 2 else 'ordinaryGrayRouter',
                    'layer': 'inner' if index < 2 else None, 'level': level,
                    'infrastructure': True} for index, name in enumerate(owner_names)]
        result[variant] = {'ownerNames': owner_names, 'deviceData': native_devices,
            'ifaceData': native_ifaces, 'devices': devices, 'interfaces': interfaces,
            'routes': routes, 'links': links, 'macIfaces': mac_ifaces,
            'mkaPeers': endpoints, 'tunnels': tunnels, 'macFrames': frames,
            'sourceIfaces': sources, 'sourceAddresses': addresses,
            'networks': [{'id': 'red-' + str(index), 'site': 'site-' + str(index),
                'level': level, 'innerComponents': [names[index]]} for index in range(2)]}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    source_path = Path(args.source)
    source = json.loads(source_path.read_text())
    destination = Path(args.output)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / 'MkaParametersLive.json').write_bytes(source_path.read_bytes())
    profiles = build_profiles(source)
    (destination / 'MacsecProtectionProfiles.json').write_text(json.dumps(profiles, indent=2) + '\n')
    provenance = {'source': str(source_path), 'sourceSha256': hashlib.sha256(source_path.read_bytes()).hexdigest(),
        'parser': source['projectionVersion'], 'scope': 'Explicit model profiles using observed per-peer settings and SCI. Extra routes, source attachments and MACsec frame bytes are model fixtures. Frame bytes establish abstract SecTAG shape, not cryptographic ciphertext correspondence.',
        'abstractKeys': 'Nonsecret model-key identifiers and synthetic test vectors; no captured secrets are retained.'}
    (destination / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')


if __name__ == '__main__':
    main()
