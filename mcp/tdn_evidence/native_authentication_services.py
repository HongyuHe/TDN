"""Bind captured certificate authentication to public CA identities."""
import hashlib
import json
from pathlib import Path
import re

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from . import native_keys
from .eap import export_report, query_report
from .parsers.snapshot import require


CAPABILITIES = ["devices", "authorities", "authentication_services", "phases"]
LEAN_VIEW = "native_authentication_services"
SCOPE = "Public logical CA identities, captured trust configuration and authenticated native IPsec session bindings"


def configuration_fields(text):
    sections, stack = {}, []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if match := re.fullmatch(r'([\w-]+)\s*\{', line):
            stack.append(match[1])
            require(tuple(stack) not in sections, "Duplicate configuration section")
            sections[tuple(stack)] = {}
        elif line == '}':
            require(bool(stack), "Unbalanced configuration section")
            stack.pop()
        elif match := re.fullmatch(r'([\w-]+)\s*=\s*([^{}#]+)', line):
            require(bool(stack), "Configuration value outside section")
            fields = sections[tuple(stack)]
            require(match[1] not in fields, "Duplicate configuration field")
            fields[match[1]] = match[2].strip()
        else:
            raise ValueError("Unsupported certificate configuration syntax")
    require(not stack, "Unclosed configuration section")
    return sections


def loaded_fields(text, section):
    matches = re.findall(r'\b' + re.escape(section) + r'\s*\{([^{}]*)\}', text)
    require(len(matches) == 1, "Missing or duplicate loaded authentication section")
    rest, fields = matches[0].strip(), {}
    while rest:
        match = re.match(r'([\w-]+)=', rest)
        require(match is not None and match[1] not in fields, "Unsupported loaded authentication field")
        name, rest = match[1], rest[match.end():]
        if rest.startswith('['):
            end = rest.find(']')
            require(end >= 0, "Unclosed loaded authentication list")
            value, rest = rest[:end + 1], rest[end + 1:].strip()
        else:
            next_field = re.search(r'\s+[\w-]+=', rest)
            end = next_field.start() if next_field else len(rest)
            value, rest = rest[:end], rest[end:].strip()
        require(bool(value), "Empty loaded authentication field")
        fields[name] = value
    return fields


def certificate(text):
    require(re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*', text)
            is not None, "Expected one public PEM certificate")
    cert = x509.load_pem_x509_certificate(text.encode())
    der = cert.public_bytes(Encoding.DER)
    def extension(kind):
        try:
            return cert.extensions.get_extension_for_class(kind).value
        except x509.ExtensionNotFound:
            return None
    basic = extension(x509.BasicConstraints)
    ski, aki = extension(x509.SubjectKeyIdentifier), extension(x509.AuthorityKeyIdentifier)
    usage = extension(x509.KeyUsage)
    alternative_names = extension(x509.SubjectAlternativeName)
    return cert, {"der": der.hex(), "sha256": hashlib.sha256(der).hexdigest(),
                  "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                  "serialNumber": str(cert.serial_number),
                  "dnsNames": alternative_names.get_values_for_type(x509.DNSName) if alternative_names else [],
                  "subjectKeyIdentifier": ski.digest.hex() if ski else None,
                  "authorityKeyIdentifier": aki.key_identifier.hex() if aki and aki.key_identifier else None,
                  "basicConstraints": {"ca": basic.ca, "pathLength": basic.path_length} if basic else None,
                  "keyCertSign": usage.key_cert_sign if usage else None,
                  "notBeforeUTC": cert.not_valid_before_utc.isoformat(),
                  "notAfterUTC": cert.not_valid_after_utc.isoformat()}


def parse(directory):
    root = Path(directory)
    manifest, native = native_keys.parse(root)
    capture = json.loads((root / 'correlation.json').read_text())
    observations = json.loads((root / 'observations.json').read_text())
    by_id = {row['id']: row for row in observations}
    authentication = {row['device']: row for row in native['authentication']}
    raw_ids, authorities, services, phases = set(), {}, [], []
    public = {}
    commands = {'sas': ['swanctl', '--list-sas', '--raw'],
                'configuration': ['cat', '/etc/swanctl/swanctl.conf'],
                'connections': ['swanctl', '--list-conns', '--raw'],
                'leafCertificate': ['cat', '/etc/swanctl/x509/cert.pem'],
                'caCertificate': ['cat', '/etc/swanctl/x509ca/ca.pem'],
                'certificates': ['swanctl', '--list-certs', '--raw']}

    def observed(record, kind):
        row = by_id[record['observations'][kind]]
        require(row['device'] == record['id'] and row['kind'] == kind and row['returncode'] == 0
                and row['command'] == ['docker', 'exec', record['id'], *commands[kind]],
                "Certificate/trust observation is not bound to its command and device")
        raw_ids.add(row['id'])
        return row

    for record in capture['phases'][0]['devices']:
        leaf_row, ca_row, loaded_row = [observed(record, kind)
                                       for kind in ['leafCertificate', 'caCertificate', 'certificates']]
        leaf, leaf_data = certificate(leaf_row['stdout'])
        ca, ca_data = certificate(ca_row['stdout'])
        require(ca_data['basicConstraints'] is not None and ca_data['basicConstraints']['ca']
                and ca_data['keyCertSign'] is True, "Selected authority is not a signing CA")
        require(leaf_data['basicConstraints'] is not None and not leaf_data['basicConstraints']['ca'],
                "Selected local certificate is not an endpoint certificate")
        require(ca.subject == ca.issuer, "Intermediate CA chains require a richer adapter")
        require(leaf_data['authorityKeyIdentifier'] is not None
                and leaf_data['authorityKeyIdentifier'] == ca_data['subjectKeyIdentifier'],
                "Leaf authority key identifier differs from selected CA")
        try:
            ca.verify_directly_issued_by(ca)
            leaf.verify_directly_issued_by(ca)
        except Exception as error:
            raise ValueError("Selected CA does not verify the captured certificate signature") from error
        require('data=0x' + ca_data['der'] in loaded_row['stdout'], "Selected CA certificate is not loaded")
        require(leaf_data['sha256'] == authentication[record['id']]['localCertificate']['sha256'],
                "Local certificate differs from authenticated native epoch")
        public[record['id']] = (leaf, leaf_data, ca, ca_data, leaf_row, ca_row, loaded_row)
        authority_id = 'ca-sha256:' + ca_data['sha256']
        authorities.setdefault(authority_id, ca_data | {"id": authority_id, "kind": "logical-certificate-authority",
            "runningServiceObserved": False, "observedOn": []})['observedOn'].append(
                {"device": record['id'], "observation": ca_row['id'], "path": commands['caCertificate'][1]})

    for phase in capture['phases']:
        phases.append({key: phase[key] for key in ['id', 'startedAt', 'endedAt']})
        for record in phase['devices']:
            device = record['id']
            auth = authentication[device]
            leaf, leaf_data, ca, ca_data, leaf_row, ca_row, loaded_row = public[device]
            peer_leaf, peer_data, *_ = public[auth['peerDevice']]
            config_row, connections = observed(record, 'configuration'), observed(record, 'connections')
            sa_row = observed(record, 'sas')
            current_sa = native_keys.association(sa_row['stdout'])
            require(all(current_sa[key] == auth['ike'][key] for key in
                        ['name', 'uniqueid', 'local-id', 'remote-id', 'local-host', 'remote-host'])
                    and current_sa['child']['uniqueid'] == auth['ike']['child']['uniqueid'],
                    'Authentication session changed between certificate observation phases')
            sections = configuration_fields(config_row['stdout'])
            connection = auth['ike']['name']
            prefix = ('connections', connection)
            require({path[1] for path in sections if len(path) > 1 and path[0] == 'connections'} == {connection},
                    "Expected the single authenticated connection")
            require({path[-1] for path in sections if len(path) == 3 and path[:2] == prefix
                     and path[-1].startswith(('local', 'remote'))} == {'local', 'remote'},
                    'Unsupported configured authentication alternatives')
            local, remote = sections.get(prefix + ('local',)), sections.get(prefix + ('remote',))
            require(local is not None and remote is not None
                    and set(local) == {'auth', 'certs', 'id'}
                    and set(remote) == {'auth', 'id', 'cacerts', 'revocation'},
                    "Unsupported certificate authentication configuration")
            require(local['auth'] == remote['auth'] == 'ecdsa-384-sha384'
                    and local['certs'] == 'cert.pem' and remote['cacerts'] == 'ca.pem'
                    and remote['revocation'] == 'strict', "Certificate/trust selection differs")
            require(sections[prefix]['version'] == '2'
                    and sections[prefix]['local_addrs'] == auth['ike']['local-host']
                    and sections[prefix]['remote_addrs'] == auth['ike']['remote-host']
                    and local['id'] == auth['ike']['local-id'] and remote['id'] == auth['ike']['remote-id'],
                    "Configured peer differs from active authenticated IKE session")
            require(local['id'] in leaf_data['dnsNames'] and remote['id'] in peer_data['dnsNames'],
                    'IKE identity is absent from the selected certificate DNS names')
            require(re.findall(r'\b(?:local|remote)-\d+\s*\{', connections['stdout']) == ['local-1 {', 'remote-1 {']
                    and connections['stdout'].count('list-conn event {') == 1
                    and 'list-conn event {' + connection + ' {' in connections['stdout'],
                    "Unexpected loaded authentication alternatives")
            loaded_local = loaded_fields(connections['stdout'], 'local-1')
            loaded_remote = loaded_fields(connections['stdout'], 'remote-1')
            require(loaded_local == {'id': local['id'], 'class': 'public key', 'groups': '[]', 'cert_policy': '[]',
                                     'certs': '[' + leaf_data['subject'] + ']', 'cacerts': '[]'}
                    and loaded_remote == {'id': remote['id'], 'class': 'public key', 'revocation': 'GOOD',
                                          'groups': '[]', 'cert_policy': '[]', 'certs': '[]',
                                          'cacerts': '[' + ca_data['subject'] + ']'},
                    "Loaded authentication or trust reference differs from configuration")
            require(peer_data['sha256'] == auth['peerCertificate']['sha256']
                    and peer_data['authorityKeyIdentifier'] == ca_data['subjectKeyIdentifier'],
                    "Authenticated peer differs from selected trust authority")
            try:
                peer_leaf.verify_directly_issued_by(ca)
            except Exception as error:
                raise ValueError("Selected trust CA does not verify the peer certificate signature") from error
            services.append({"device": device, "peerDevice": auth['peerDevice'], "phase": phase['id'],
                "epoch": native['manifestSha256'], "connection": connection,
                "ikeUniqueId": auth['ike']['uniqueid'], "childUniqueId": auth['ike']['child']['uniqueid'],
                "certificateAuthenticated": True, "preSharedCAKAuthenticated": False,
                "localAuth": local['auth'], "remoteAuth": remote['auth'],
                "authorityId": 'ca-sha256:' + ca_data['sha256'], "authority": ca_data,
                "localCertificate": leaf_data, "peerCertificate": peer_data,
                "configObservation": config_row['id'], "loadedConnectionObservation": connections['id'],
                "caObservation": ca_row['id'], "leafObservation": leaf_row['id'],
                "loadedCertificatesObservation": loaded_row['id'], "authenticationLogObservation": auth['logObservation'],
                "saObservation": sa_row['id'], "authenticationSAObservation": auth['saObservation'],
                "certificateFile": local['certs'],
                "trustFile": remote['cacerts'], "trustDirectory": '/etc/swanctl/x509ca',
                "certificateDirectory": '/etc/swanctl/x509', "revocationPolicy": remote['revocation'],
                "publicIssuerSignaturesChecked": True,
                "scope": "Logical signing/trust identity; no CA service, current validity or complete certificate-path validation claim."})
    raw_ids.update(row['logObservation'] for row in authentication.values())
    raw_ids.update(row['saObservation'] for row in authentication.values())
    report = {"devices": native['devices'], "authorities": list(authorities.values()),
              "authentication_services": services, "phases": phases,
              "manifestSha256": native['manifestSha256'], "rawObservationIds": sorted(raw_ids),
              "projectionVersion": 'native-authentication-services-v1',
              "scope": ["Public CA identities and selected trust references in the exact retained native IPsec epoch.",
                        "Signature comparisons are performed by the adapter's cryptographic library, outside Lean.",
                        "No running CA container, private CA key custody, institutional approval or present-time revocation/validity claim.",
                        "The daemon authentication and active CHILD_SA binding are inherited from the native key adapter."]}
    return manifest, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    require(observation in report['rawObservationIds'], "Observation is outside validated CA capture")
    rows = json.loads((Path(directory) / 'observations.json').read_text())
    row = next(row for row in rows if row['id'] == observation)
    return row.get('stderr' if stderr else 'stdout', '')


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
