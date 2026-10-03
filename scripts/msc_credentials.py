"""Retain bounded public credential, connection, and IKE-session evidence."""

import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re


def parse_time(value):
    cleaned = ' '.join(value.replace('UTC ', '').split())
    return int(datetime.strptime(cleaned, '%b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp())


def validity_field(value, marker):
    match = re.fullmatch(re.escape(marker) + r'\s+(.+?),\s*(.+)', value.strip())
    if match is None:
        raise ValueError('unsupported certificate validity field')
    status = match[2].split(' (', 1)[0]
    return parse_time(match[1]), status


def exact_fields(value, names, context):
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValueError('unsupported fields in ' + context)


def natural(value):
    if type(value) is not int or value < 0:
        raise ValueError('credential natural number expected')
    return value


def boolean(value):
    if type(value) is not bool:
        raise ValueError('credential Boolean expected')
    return value


def string(value):
    if not isinstance(value, str):
        raise ValueError('credential string expected')
    return value


def string_list(value):
    if not isinstance(value, list):
        raise ValueError('credential string list expected')
    return [string(v) for v in value]


def fingerprint(value):
    if not re.fullmatch('[0-9a-f]{64}', string(value)):
        raise ValueError('invalid public credential fingerprint')
    return value


def pem_fingerprints(text):
    found = list(re.finditer(r'-----BEGIN (CERTIFICATE|X509 CRL)-----\s*([A-Za-z0-9+/=\s]+?)-----END \1-----', text))
    if re.sub(r'-----BEGIN (CERTIFICATE|X509 CRL)-----\s*[A-Za-z0-9+/=\s]+?-----END \1-----', '', text).strip():
        raise ValueError('unsupported public PEM data')
    result = {'CERTIFICATE': [], 'X509 CRL': []}
    for item in found:
        raw = base64.b64decode(''.join(item[2].split()), validate=True)
        result[item[1]].append(hashlib.sha256(raw).hexdigest())
    return result


def parse_verifications(values):
    result = []
    if not isinstance(values, list):
        raise ValueError('credential verification list expected')
    for value in values:
        exact_fields(value, 'anchor valid error', 'public verification')
        result.append(dict(anchor=fingerprint(value['anchor']), valid=boolean(value['valid']), error=string(value['error'])))
    return result


def parse_audit(text, pem, trusted):
    audit = json.loads(text)
    exact_fields(audit, 'at_epoch pem_sha256 anchors certificates crls', 'public audit')
    if fingerprint(audit['pem_sha256']) != hashlib.sha256(pem.encode()).hexdigest():
        raise ValueError('public PEM and audit hash differ')
    public_ids, trusted_ids = pem_fingerprints(pem), pem_fingerprints(trusted)
    anchors = [fingerprint(v) for v in string_list(audit['anchors'])]
    if sorted(anchors) != sorted(trusted_ids['CERTIFICATE']) or trusted_ids['X509 CRL']:
        raise ValueError('public audit anchors differ from configured trust file')
    certs, crls = [], []
    for c in audit['certificates']:
        uri_fields = 'crl_distribution_points ocsp_servers issuing_certificate_urls'
        has_uris = bool(set(c) & set(uri_fields.split()))
        exact_fields(c, 'fingerprint subject issuer serial not_before not_after public_key_algorithm public_key_bits curve signature_algorithm is_ca basic_constraints_valid key_usage extended_key_usage unknown_extended_key_usage unhandled_critical_extensions dns_names subject_key_id authority_key_id verifications' + (' ' + uri_fields if has_uris else ''), 'public certificate audit')
        certs.append(dict(fingerprint=fingerprint(c['fingerprint']), subject=string(c['subject']), issuer=string(c['issuer']),
            serial=string(c['serial']), notBefore=natural(c['not_before']), notAfter=natural(c['not_after']),
            publicKeyAlgorithm=string(c['public_key_algorithm']), publicKeyBits=natural(c['public_key_bits']), curve=string(c['curve']),
            signatureAlgorithm=string(c['signature_algorithm']), isCA=boolean(c['is_ca']), basicConstraintsValid=boolean(c['basic_constraints_valid']),
            keyUsage=natural(c['key_usage']), extendedKeyUsage=[natural(v) for v in c['extended_key_usage']],
            unknownExtendedKeyUsage=string_list(c['unknown_extended_key_usage']), unhandledCriticalExtensions=string_list(c['unhandled_critical_extensions']),
            dnsNames=string_list(c['dns_names']), subjectKeyId=string(c['subject_key_id']), authorityKeyId=string(c['authority_key_id']),
            verifications=parse_verifications(c['verifications']),
            crlDistributionPoints=string_list(c['crl_distribution_points']) if has_uris else None,
            ocspServers=string_list(c['ocsp_servers']) if has_uris else None,
            issuingCertificateURLs=string_list(c['issuing_certificate_urls']) if has_uris else None))
    for c in audit['crls']:
        exact_fields(c, 'fingerprint issuer authority_key_id this_update next_update number signature_algorithm revoked_serials verifications', 'public CRL audit')
        crls.append(dict(fingerprint=fingerprint(c['fingerprint']), issuer=string(c['issuer']), authorityKeyId=string(c['authority_key_id']),
            thisUpdate=natural(c['this_update']), nextUpdate=natural(c['next_update']), number=int(string(c['number']),16),
            signatureAlgorithm=string(c['signature_algorithm']), revokedSerials=string_list(c['revoked_serials']),
            verifications=parse_verifications(c['verifications'])))
    if sorted(c['fingerprint'] for c in certs) != sorted(public_ids['CERTIFICATE']) or sorted(c['fingerprint'] for c in crls) != sorted(public_ids['X509 CRL']):
        raise ValueError('public audit omits or adds PEM objects')
    return dict(atEpoch=natural(audit['at_epoch']), pemSHA256=audit['pem_sha256'], anchors=anchors, certificates=certs, crls=crls)


def chunks(text, pattern):
    headers = list(re.finditer(pattern, text, re.M))
    preamble = text[:headers[0].start()] if headers else text
    if preamble.strip():
        raise ValueError('unsupported inventory preamble')
    return [(m, text[m.end():headers[i+1].start() if i+1 < len(headers) else len(text)]) for i,m in enumerate(headers)]


def only(pattern, text, context):
    found = list(re.finditer(pattern, text, re.M))
    if len(found) != 1:
        raise ValueError('missing or ambiguous ' + context)
    return found[0]


def addresses(value):
    return [int(ipaddress.IPv4Address(v.strip())) for v in value.split(',')]


def selectors(value):
    result = []
    for item in value.split():
        cidr = ipaddress.IPv4Network(item, strict=False)
        result.append(dict(address=int(cidr.network_address), length=cidr.prefixlen))
    return result


def parse_connections(text):
    result = []
    pattern = r'^(\S+): IKEv(\d+), (?:reauthentication every (\d+)s|no reauthentication), (?:rekeying every (\d+)s|no rekeying), dpd delay (\d+)s\s*$'
    for header, body in chunks(text, pattern):
        parent, *children = re.split(r'(?m)(?=^  \S+: (?:TUNNEL|TRANSPORT),)', body)
        local = only(r'^  local:\s+(.+)$', parent, 'connection local addresses')
        remote = only(r'^  remote:\s+(.+)$', parent, 'connection remote addresses')
        auth = r'  local (.+) authentication:\n    id: (.+)\n    certs: (.+)\n  remote (.+) authentication:\n    id: (.+)\n    cacerts: (.+)\n?'
        match = only('^'+auth, parent, 'connection authentication')
        remaining = parent
        for item in [local, remote, match]:
            remaining = remaining.replace(item[0], '', 1)
        if remaining.strip():
            raise ValueError('unsupported connection fields')
        parsed = []
        for child in children:
            match_child = re.fullmatch(r'  (\S+): (TUNNEL|TRANSPORT), rekeying every (\d+)s, dpd action is (\S+)\n    local:\s+(.+)\n    remote:\s+(.+)\n?\s*', child)
            if match_child is None:
                raise ValueError('unsupported loaded child connection')
            parsed.append(dict(name=match_child[1], mode=match_child[2], rekeySeconds=int(match_child[3]), dpdAction=match_child[4],
                localSelectors=selectors(match_child[5]), remoteSelectors=selectors(match_child[6])))
        result.append(dict(name=header[1], version=int(header[2]), reauthIntervalSeconds=int(header[3] or 0), ikeRekeyIntervalSeconds=int(header[4] or 0),
            dpdSeconds=int(header[5]), localAddresses=addresses(local[1]), remoteAddresses=addresses(remote[1]),
            localAuth=match[1], localIdentity=match[2], localCertificate=match[3], remoteAuth=match[4], remoteIdentity=match[5], remoteCA=match[6], children=parsed))
    return result


def parse_sessions(text):
    result = []
    pattern = r'^(\S+): #(\d+), ([A-Z_]+), IKEv(\d+), ([0-9a-f]+)_i(\*?) ([0-9a-f]+)_r(\*?)\s*$'
    for header, body in chunks(text, pattern):
        parent, *children = re.split(r'(?m)(?=^  \S+: #\d+, reqid )', body)
        local = only(r"^  local\s+'([^']+)' @ (\S+)\[(\d+)\]\s*$", parent, 'session local identity')
        remote = only(r"^  remote\s+'([^']+)' @ (\S+)\[(\d+)\]\s*$", parent, 'session remote identity')
        proposal = only(r'^  ([A-Z][A-Z0-9_/-]+)\s*$', parent, 'IKE proposal')
        timing = only(r'^  established (\d+)s ago(?:, reauth in (\d+)s)?(?:, rekeying in (\d+)s)?\s*$', parent, 'IKE timers')
        remaining = parent
        for item in [local,remote,proposal,timing]:
            remaining = remaining.replace(item[0], '', 1)
        if remaining.strip():
            raise ValueError('unsupported IKE session fields')
        parsed = []
        for child in children:
            heading = only(r'^  (\S+): #(\d+), reqid (\d+), ([A-Z_]+), ([A-Z_]+), ESP:(\S+)\s*$',child,'CHILD header')
            clock = only(r'^    installed (\d+)s ago, rekeying in (\d+)s, expires in (\d+)s\s*$',child,'CHILD timers')
            counters = []
            for direction in ['in','out']:
                counter = only(r'^    '+direction+r'\s+([0-9a-f]+),\s+(\d+) bytes,\s+(\d+) packets(?:,\s+(\d+)s ago)?\s*$',child,'CHILD counter')
                counters.append(counter)
            ls = only(r'^    local\s+(.+)$',child,'CHILD local selectors')
            rs = only(r'^    remote\s+(.+)$',child,'CHILD remote selectors')
            remaining = child
            for item in [heading,clock,*counters,ls,rs]:
                remaining = remaining.replace(item[0], '', 1)
            if remaining.strip():
                raise ValueError('unsupported CHILD SA fields')
            parsed.append(dict(name=heading[1], uniqueId=int(heading[2]), reqid=int(heading[3]), state=heading[4], mode=heading[5], proposal=heading[6],
                installedSeconds=int(clock[1]), rekeySeconds=int(clock[2]), expiresSeconds=int(clock[3]),
                inboundSPI=int(counters[0][1],16), outboundSPI=int(counters[1][1],16),
                inboundBytes=int(counters[0][2]), outboundBytes=int(counters[1][2]), inboundPackets=int(counters[0][3]), outboundPackets=int(counters[1][3]),
                inboundLastSeconds=None if counters[0][4] is None else int(counters[0][4]), outboundLastSeconds=None if counters[1][4] is None else int(counters[1][4]),
                localSelectors=selectors(ls[1]),remoteSelectors=selectors(rs[1])))
        result.append(dict(name=header[1], uniqueId=int(header[2]), state=header[3], version=int(header[4]), initiatorSPI=header[5], responderSPI=header[7],
            initiator=bool(header[6]), responder=bool(header[8]), localIdentity=local[1], remoteIdentity=remote[1],
            localAddress=int(ipaddress.IPv4Address(local[2])), remoteAddress=int(ipaddress.IPv4Address(remote[2])), localPort=int(local[3]), remotePort=int(remote[3]),
            proposal=proposal[1], establishedSeconds=int(timing[1]), reauthSeconds=None if timing[2] is None else int(timing[2]), ikeRekeySeconds=None if timing[3] is None else int(timing[3]), children=parsed))
    return result


def render_record(value, record, sequence, optional, quoted, key=None):
    if value is None:
        return 'none'
    if key in {'crlDistributionPoints', 'ocspServers', 'issuingCertificateURLs'}:
        return optional(value, lambda values: sequence(quoted(v) for v in values))
    if key in {'inboundLastSeconds','outboundLastSeconds','reauthSeconds','ikeRekeySeconds'} and not isinstance(value, (dict,list)):
        return optional(value, str)
    if isinstance(value,bool):
        return str(value).lower()
    if isinstance(value,int):
        return str(value)
    if isinstance(value,str):
        return quoted(value)
    if isinstance(value,list):
        return sequence(render_record(v,record,sequence,optional,quoted) for v in value)
    return record(**{k:render_record(v,record,sequence,optional,quoted,k) for k,v in value.items()})


def parse_vici_inventory(text, event_prefix, completion):
    """Decode the bounded VICI pretty-raw inventory without dropping fields."""
    def object_body(value, position):
        result = {}
        while True:
            while position < len(value) and value[position].isspace():
                position += 1
            if position < len(value) and value[position] == '}':
                return result, position + 1
            field = re.match(r'([^\s={}\[\]]+)\s*([={])', value[position:])
            if field is None or field[1] in result:
                raise ValueError('unsupported or repeated VICI field')
            position += field.end()
            if field[2] == '{':
                item, position = object_body(value, position)
            elif value[position:position+1] == '[':
                end = value.find(']', position)
                if end == -1 or '[' in value[position+1:end]:
                    raise ValueError('unsupported VICI array')
                item = value[position+1:end]
                position = end + 1
            else:
                boundary = re.search(r'\s+(?=[^\s={}\[\]]+\s*[={])|(?=})', value[position:])
                if boundary is None:
                    raise ValueError('unterminated VICI scalar')
                item = value[position:position+boundary.start()].strip()
                position += boundary.start()
            result[field[1]] = item
    connections = []
    reply = False
    for line in text.splitlines():
        if not line.strip():
            continue
        if line == completion:
            if reply:
                raise ValueError('duplicate VICI connection reply')
            reply = True
            continue
        if not line.startswith(event_prefix + '{') or reply:
            raise ValueError('unsupported VICI connection response')
        value = line[len(event_prefix):]
        fields, end = object_body(value, 1)
        if value[end:].strip() or len(fields) != 1:
            raise ValueError('invalid VICI connection event')
        name, connection = next(iter(fields.items()))
        connections.append((name, connection))
    if not reply:
        raise ValueError('missing VICI connection completion')
    return connections


def parse_vici_connections(text):
    return parse_vici_inventory(text, 'list-conn event ', 'list-conns reply {}')


def parse_authorities(text):
    result = []
    for name, record in parse_vici_inventory(text, 'list-authority event ', 'list-authorities reply {}'):
        exact_fields(record, 'cacert crl_uris ocsp_uris cert_uri_base', 'loaded authority')
        result.append(dict(name=name, certificate=string(record['cacert']),
                           crlURIs=string(record['crl_uris']).split(),
                           ocspURIs=string(record['ocsp_uris']).split(),
                           certificateURIBase=string(record['cert_uri_base'])))
    return result


def parse_service_configuration(text, owner):
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError('service configuration object required')
    #* The optional management description never gates the retained policy.
    value.pop('management', None)
    exact_fields(value, 'external_interface local_address peer_address external_local_protocols revocation_delivery clock', 'service configuration')
    return dict(device=owner, externalInterface=string(value['external_interface']),
                localAddress=int(ipaddress.IPv4Address(string(value['local_address']))),
                peerAddress=int(ipaddress.IPv4Address(string(value['peer_address']))),
                localProtocols=string_list(value['external_local_protocols']),
                revocationDelivery=string(value['revocation_delivery']), clock=string(value['clock']))


def bind_connection_details(connections, raw):
    records = parse_vici_connections(raw)
    if len(records) != len(connections):
        raise ValueError('text and VICI connection counts differ')
    for connection, (name, detail) in zip(connections, records):
        exact_fields(detail, 'local_addrs remote_addrs version reauth_time rekey_time unique dpd_delay local-1 remote-1 children', 'loaded VICI connection')
        if name != connection['name'] or detail['version'] != 'IKEv'+str(connection['version']):
            raise ValueError('text and VICI connection identities differ')
        for key, expected in [('local_addrs', connection['localAddresses']), ('remote_addrs', connection['remoteAddresses'])]:
            if addresses(detail[key]) != expected:
                raise ValueError('text and VICI connection addresses differ')
        for key, expected in [('reauth_time','reauthIntervalSeconds'), ('rekey_time','ikeRekeyIntervalSeconds'), ('dpd_delay','dpdSeconds')]:
            if int(detail[key]) != connection[expected]:
                raise ValueError('text and VICI connection timers differ')
        local, remote = detail['local-1'], detail['remote-1']
        exact_fields(local, 'id class groups cert_policy certs cacerts', 'local VICI authentication')
        exact_fields(remote, 'id class revocation groups cert_policy certs cacerts', 'remote VICI authentication')
        for value in [local, remote]:
            if value['groups'] or value['cert_policy']:
                raise ValueError('unsupported VICI group or certificate policy constraint')
        for actual, expected in [(local['id'],connection['localIdentity']), (remote['id'],connection['remoteIdentity']),
                                 (local['class'],connection['localAuth']), (remote['class'],connection['remoteAuth']),
                                 (local['certs'],connection['localCertificate']), (remote['cacerts'],connection['remoteCA'])]:
            if actual != expected:
                raise ValueError('text and VICI authentication differ')
        if local['cacerts'] or remote['certs']:
            raise ValueError('unsupported additional VICI authentication constraint')
        connection['revocation'] = remote['revocation']
        connection['uniquePolicy'] = detail['unique']
        if list(detail['children']) != [c['name'] for c in connection['children']]:
            raise ValueError('text and VICI child inventory differ')
        for child in connection['children']:
            actual = detail['children'][child['name']]
            exact_fields(actual, 'mode rekey_time rekey_bytes rekey_packets dpd_action close_action local-ts remote-ts', 'loaded VICI child')
            if actual['mode'] != child['mode'] or int(actual['rekey_time']) != child['rekeySeconds'] or actual['dpd_action'] != child['dpdAction']:
                raise ValueError('text and VICI child settings differ')
            if selectors(actual['local-ts']) != child['localSelectors'] or selectors(actual['remote-ts']) != child['remoteSelectors']:
                raise ValueError('text and VICI child selectors differ')
            child['rekeyBytes'] = natural(int(actual['rekey_bytes']))
            child['rekeyPackets'] = natural(int(actual['rekey_packets']))
            child['closeAction'] = actual['close_action']
    return connections


def parse_reported_crls(text):
    marker = 'List of X.509 CRLs'
    if text.count(marker) != 1:
        raise ValueError('missing/ambiguous reported CRL section')
    body = text.split(marker, 1)[1]
    result = []
    for heading, record in chunks(body, r'^  issuer:\s+"([^"\n]+)"[ \t]*$'):
        updated = only(r'^  update:\s+(this on .+)$', record, 'CRL issue time')
        expires = only(r'^\s+(next on .+)$', record, 'CRL expiry time')
        serial = only(r'^  serial:\s+([0-9a-fA-F:]+)[ \t]*$', record, 'CRL number')
        authority = only(r'^  authKeyId:\s+([0-9a-fA-F:]+)[ \t]*$', record, 'CRL authority')
        count = only(r'^  (\d+) revoked certificates:?[ \t]*$', record, 'CRL revoked count')
        remaining = record
        for item in [updated,expires,serial,authority,count]:
            remaining = remaining.replace(item[0], '', 1)
        revoked = []
        for line in remaining.splitlines():
            if not line.strip():
                continue
            match = re.fullmatch(r'    ([0-9a-fA-F:]+): (.+), (.+)', line)
            if match is None:
                raise ValueError('unsupported CRL revoked entry')
            revoked.append(dict(serial=format(int(match[1].replace(':',''),16),'x'), atEpoch=parse_time(match[2]), reason=match[3]))
        if len(revoked) != int(count[1]):
            raise ValueError('CRL revoked count differs from entries')
        issued, issue_status = validity_field(updated[1],'this on')
        expiration, expiry_status = validity_field(expires[1],'next on')
        result.append(dict(issuer=heading[1], thisUpdate=issued, nextUpdate=expiration,
            thisUpdateStatus=issue_status, nextUpdateStatus=expiry_status,
            number=int(serial[1].replace(':',''),16), authorityKeyId=authority[1].replace(':','').lower(), revoked=revoked))
    return result
