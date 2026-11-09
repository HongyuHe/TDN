"""Bind active native CHILD_SAs to privately compared kernel key material."""
import hashlib
import json
from pathlib import Path
import re
import ssl

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ['devices', 'interfaces', 'associations', 'authentication', 'phases']
LEAN_VIEW = 'native_ipsec_keys'
SCOPE = 'Two sequential observations of active authenticated IPsec associations and private peer-key equality'
FIELDS = re.compile(r'([\w-]+)=(\[[^\]]*\]|[^\s{}]+)')


def fields(text):
    pairs = FIELDS.findall(text)
    require(len(pairs) == len(dict(pairs)), 'Duplicate VICI field')
    require(not FIELDS.sub('', text).strip(), 'Unsupported VICI field syntax')
    return dict(pairs)


def association(text):
    match = re.fullmatch(r'list-sa event \{(\S+) \{(.*?) child-sas \{(\S+) \{(.*?)\}\}\}\}\s*list-sas reply \{\}\s*', text, re.S)
    require(match is not None, 'Expected exactly one active IKE and CHILD association')
    name, parent, child_name, child = match.groups()
    parent, child = fields(parent), fields(child)
    require(parent['state'] == 'ESTABLISHED' and parent['version'] == '2' and
            child['state'] == 'INSTALLED' and child['mode'] == 'TUNNEL' and child['protocol'] == 'ESP',
            'IpsecPolicy is not active IKEv2 tunnel ESP')
    require(child['encr-alg'] == 'AES_GCM_16' and child['encr-keysize'] == '256',
            'Unsupported CHILD cryptographic transform')
    for key in ['local-ts', 'remote-ts']:
        require(re.fullmatch(r'\[[0-9a-fA-F:./]+(?: [0-9a-fA-F:./]+)*\]', child[key]) is not None,
                'Unsupported CHILD selector')
    return parent | {'name': name, 'childName': child_name, 'child': child}


def blocks(text):
    result = []
    for block in re.split(r'(?m)(?=^src )', text):
        if not block.strip():
            continue
        match = re.search(r'^src (\S+) dst (\S+)\s+proto (\S+) spi (0x[0-9a-f]+)(?:\(\d+\))? reqid (\d+)(?:\(0x[0-9a-f]+\))? mode (\S+)', block)
        require(match is not None, 'Unsupported public kernel association')
        source, destination, protocol, spi, reqid, mode = match.groups()
        require(not re.search(r'(?m)^\s*(mark|if_id)\b', block), 'Marked or interface-ID associations require another parser')
        result.append(((source, destination, protocol, int(spi, 16), int(reqid), mode), block))
    return result


def identity(binding):
    return tuple(binding[k] for k in ['source', 'destination', 'protocol', 'spi', 'reqid', 'mode'])


def parse(directory):
    directory = Path(directory)
    manifest_hash = validate_files(directory)
    manifest = json.loads((directory / 'manifest.json').read_text())
    capture = json.loads((directory / 'correlation.json').read_text())
    spec = json.loads((directory / 'spec.json').read_text())
    observations = json.loads((directory / 'observations.json').read_text())
    require(manifest['schema'] == capture['schema'] == 'native-ipsec-correlation/v1' and
            manifest['errors'] == capture['errors'] == [], 'Failed or unknown native capture')
    by_id = {o['id']: o for o in observations}
    require(len(by_id) == len(observations), 'Duplicate observation ID')
    devices = {d['id']: d for d in spec['devices'] if d['role'] in ['inner', 'outer']}
    require(len(capture['phases']) == 2, 'Before and after phases are required')
    raw_ids, interfaces, auth_records, phase_records = set(), [], [], []
    certificates = {}

    def observed(record, kind):
        row = by_id[record['observations'][kind]]
        require(row['device'] == record['id'] and row['kind'] == kind and row['returncode'] == 0 and
                row['command'][:3] == ['docker', 'exec', record['id']], 'Unbound native observation')
        raw_ids.add(row['id'])
        return row

    for record in capture['phases'][0]['devices']:
        leaf = observed(record, 'leafCertificate')
        der = ssl.PEM_cert_to_DER_cert(leaf['stdout'])
        certificates[record['id']] = {'der': der.hex(), 'sha256': hashlib.sha256(der).hexdigest(),
            'observation': leaf['id']}

    for phase in capture['phases']:
        require({d['id'] for d in phase['devices']} == set(devices) and
                len(phase['devices']) == len(devices), 'Incomplete phase device inventory')
        bindings = phase['bindings']
        require(len(bindings) == 2 * len(devices) and len({b['id'] for b in bindings}) == len(bindings),
                'Incomplete or duplicate installed association inventory')
        projected = []
        for record in phase['devices']:
            device = record['id']
            addr = observed(record, 'interfaces')
            ports = json.loads(addr['stdout'])
            addresses = {a['local']: p['ifname'] for p in ports for a in p.get('addr_info', [])
                         if a['family'] in ['inet', 'inet6']}
            if phase == capture['phases'][0]:
                interfaces.extend({'device': device, 'name': p['ifname'], 'addresses': p.get('addr_info', []),
                    'observation': addr['id']} for p in ports)
            sa_row = observed(record, 'sas')
            sa = association(sa_row['stdout'])
            child = sa['child']
            states = observed(record, 'states')
            statistics = observed(record, 'statistics')
            material_row = by_id[record['observations']['materialRead']]
            require(material_row['kind'] == 'private-state-comparison' and material_row['device'] == device and
                    material_row['returncode'] == 0 and material_row['command'] == ['docker', 'exec', device, 'ip', 'xfrm', 'state'],
                    'Private comparison is not bound to the kernel read')
            raw_ids.add(material_row['id'])
            public = blocks(states['stdout'])
            stats = dict(blocks(statistics['stdout']))
            compared = blocks(material_row['stdout'])
            owned = [b for b in bindings if b['device'] == device]
            require(sorted(identity(b) for b in owned) == sorted(k for k, _ in public) ==
                    sorted(stats) == sorted(k for k, _ in compared), 'Kernel inventories differ')
            peer_devices = [p for p in capture['phases'][0]['devices'] if p['id'] != device and
                association(observed(p, 'sas')['stdout'])['local-host'] == sa['remote-host']]
            require(len(peer_devices) == 1, 'No unique native IKE peer')
            peer = peer_devices[0]
            if phase == capture['phases'][0]:
                log = observed(record, 'ikeLog')
                certs = observed(record, 'certificates')
                peer_cert = certificates[peer['id']]
                require('data=0x' + peer_cert['der'] in certs['stdout'], 'Remote public certificate is not loaded')
                required = [f"authentication of '{sa['local-id']}' (myself) with ECDSA_WITH_SHA384_DER successful",
                    f"authentication of '{sa['remote-id']}' with ECDSA_WITH_SHA384_DER successful",
                    f"IKE_SA {sa['name']}[{sa['uniqueid']}] established between {sa['local-host']}[{sa['local-id']}]...{sa['remote-host']}[{sa['remote-id']}]",
                    f"CHILD_SA {child['name']}{{{child['uniqueid']}}} established with SPIs {child['spi-in']}_i {child['spi-out']}_o and TS {child['local-ts'][1:-1]} === {child['remote-ts'][1:-1]}"]
                require(all(line in log['stdout'] for line in required), 'IKE authentication/CHILD establishment record differs')
                auth_records.append({'device': device, 'peerDevice': peer['id'], 'ike': sa,
                    'peerCertificate': peer_cert, 'localCertificate': certificates[device],
                    'logObservation': log['id'], 'saObservation': sa_row['id'],
                    'scope': 'Daemon-reported successful certificate authentication and its active CHILD_SA; no independent cryptographic verification.'})
            for binding in owned:
                incoming = binding['direction'] == 'inbound'
                require(binding['direction'] in ['inbound', 'outbound'] and binding['mark'] is None and binding['ifId'] is None,
                        'Unsupported association direction or marking')
                source = sa['remote-host'] if incoming else sa['local-host']
                destination = sa['local-host'] if incoming else sa['remote-host']
                require(identity(binding) == (source, destination, 'esp', int(child['spi-in' if incoming else 'spi-out'], 16),
                    int(child['reqid']), 'tunnel') and binding['localInterface'] == addresses[sa['local-host']],
                    'Kernel association differs from active CHILD_SA')
                require(binding['materialObservation'] == material_row['id'] and binding['publicStateObservation'] == states['id'] and
                        binding['statisticsObservation'] == statistics['id'], 'IpsecPolicy source observation differs')
                material = binding['materials']
                require(len(material) == 1 and material[0]['kind'] == 'aead' and material[0]['algorithm'] == 'rfc4106(gcm(aes))' and
                        material[0]['bytes'] == 36 and material[0]['parameters'] == '128' and
                        re.fullmatch('[0-9a-f]{64}', material[0]['sha256']) is not None,
                        'Unsupported private material reference')
                block = dict(public)[identity(binding)]
                require('aead rfc4106(gcm(aes)) <<Keys hidden>> 128' in block and
                        binding['publicBlock'].strip() == dict(compared)[identity(binding)].strip(), 'Public cryptographic state differs')
                added = re.findall(r'(?m)^\s*add (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) use ', stats[identity(binding)])
                require(len(added) == 1, 'Missing kernel installation time')
                peer_bindings = [b for b in bindings if b['id'] == binding['equalTo']]
                require(len(peer_bindings) == 1, 'Private equality peer is missing')
                paired = peer_bindings[0]
                require(paired['device'] == peer['id'] and paired['direction'] != binding['direction'] and
                        all(paired[k] == binding[k] for k in ['source', 'destination', 'protocol', 'spi', 'mode', 'materials']) and
                        paired['equalTo'] == binding['id'], 'Private peer equality conflicts with installed state')
                install = {'device': device, 'identity': list(identity(binding)), 'addedUTC': added[0], 'material': material}
                projected.append(binding | {'installedAtUTC': added[0], 'epoch': manifest_hash,
                    'installationReference': hashlib.sha256(json.dumps(install, sort_keys=True).encode()).hexdigest(),
                    'referenceOrigin': 'Derived from device, public association, reported kernel add time and private material hash.',
                    'peerDevice': peer['id'], 'child': child, 'ikeUniqueId': sa['uniqueid'],
                    'sourceSelectors': child['remote-ts' if incoming else 'local-ts'][1:-1].split(),
                    'destinationSelectors': child['local-ts' if incoming else 'remote-ts'][1:-1].split(),
                    'keyBits': 256, 'saltBytes': 4, 'icvBits': 128})
        phase_records.append({'id': phase['id'], 'startedAt': phase['startedAt'], 'endedAt': phase['endedAt'],
            'associations': projected})
    stable = lambda phase: sorted(b['installationReference'] for b in phase['associations'])
    require(stable(phase_records[0]) == stable(phase_records[1]), 'Installed association changed between phases')
    report = {'devices': list(devices.values()), 'interfaces': interfaces, 'associations': phase_records[-1]['associations'],
        'authentication': auth_records, 'phases': phase_records, 'manifestSha256': manifest_hash,
        'rawObservationIds': sorted(raw_ids), 'projectionVersion': 'native-ipsec-correlation-v1',
        'scope': [SCOPE, 'Same identities, material references and reported add times were present before and after collection.',
            'Sequential equality checks do not prove atomicity or exclude an unobserved change between reads.',
            'Private equality is a collector observation. Public hashes preserve its correlation; hashes alone do not prove key equality.']}
    return manifest | {'runtime_backend': 'native-frr-ovs-strongswan-linux'}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    require(observation in report['rawObservationIds'], 'Observation is outside validated native capture')
    rows = json.loads((Path(directory) / 'observations.json').read_text())
    row = next(row for row in rows if row['id'] == observation)
    return row.get('stderr' if stderr else 'stdout', '')


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
