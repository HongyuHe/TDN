"""Bind observed administration requests to real authenticated TLS connections."""
import hashlib
import json
from pathlib import Path
import ssl

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require

CAPABILITIES = ['devices', 'accounts', 'sessions', 'events', 'attempts', 'listeners', 'coverage', 'observations']
LEAN_VIEW = 'administration_lifecycle'
SCOPE = 'Isolated experimental identities, per-user credentials and actual TLS-channel administration'
SERVER_HASH = 'd61d9749b24cf019fdef90bcbb31efade6567be58978c0aa463c7899ac2440d4'


def parse(directory):
    root = Path(directory)
    digest = validate_files(root)
    capture = json.loads((root / 'observations.json').read_text())
    require(capture['error'] is None and capture['privateFilesRemaining'] == 0, 'Failed administration lifecycle capture')
    require(hashlib.sha256((root / 'server.py').read_bytes()).hexdigest() == SERVER_HASH, 'Unreviewed administration implementation')
    commands = capture['commands']
    by_id = {row['id']: row for row in commands}
    require(len(by_id) == len(commands), 'Duplicate administration observation')
    accounts = json.loads((root / 'accounts.json').read_text())
    require(len(accounts) == 2 and len({a['uid'] for a in accounts}) == 2 and
            len({a['certificateSha256'] for a in accounts}) == 2, 'Account inventory is incomplete or shares credentials')
    for account in accounts:
        pem = (root / (account['credentialName'] + '.pem')).read_text()
        require(hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() == account['certificateSha256'], 'Account certificate binding differs')
        created = by_id[account['unixAccountCreationObservation']]
        issued = by_id[account['creationObservation']]
        identity = by_id[account['unixIdentityObservation']]
        require(created['returncode'] == issued['returncode'] == identity['returncode'] == 0 and
                created['command'] == ['useradd', '-M', '-U', '-s', '/usr/sbin/nologin', account['login']] and
                identity['command'] == ['id', account['login']] and
                'uid=%d(%s)' % (account['uid'], account['login']) in identity['stdout'] and
                account['unixAccountCreatedOrder'] == created['endOrder'] and account['createdOrder'] == issued['endOrder'],
                'Account creation or identity does not match its command')
        require(issued['command'][:3] == ['openssl', 'x509', '-req'] and account['workstationAccount'] and not account['groupAccount'], 'Unsupported account issuance')
    events = [json.loads(line) for line in (root / 'server.jsonl').read_text().splitlines()]
    require(all(a['order'] < b['order'] for a, b in zip(events, events[1:])), 'Server event order is not strict')
    require(events[0]['kind'] == 'ready' and events[-1]['kind'] == 'stopped', 'Incomplete service lifetime')
    sessions, attempts, projected, raw = [], [], [], []
    active, revoked = {}, set()
    for index, event in enumerate(events):
        source = 'server-%04d' % index
        raw.append({'id': source, 'record': event})
        kind = event['kind']
        if kind == 'authenticationComplete':
            matching = [a for a in accounts if a['certificateSha256'] == event['certificateSha256']]
            require(len(matching) == 1 and matching[0]['person'] == event['account'], 'Authentication lacks its account')
            account = matching[0]
            require(account['createdOrder'] < event['order'] and event['protocol'] == 'TLSv1.3' and
                    event['revoked'] == (event['certificateSha256'] in revoked) and event['session'] not in active,
                    'Authentication timing, protocol, revocation or session differs')
            client = [row for row in commands if 'setpriv' in row['command'] and
                      str(event['remote'][1]) == row['command'][-1]]
            require(len(client) == 1 and client[0]['command'][client[0]['command'].index('--reuid')+1] == str(account['uid']),
                    'Client request is not bound to the observed Unix account')
            session = {'id': event['session'], 'person': account['person'], 'component': account['component'],
                'authenticationOrder': event['order'], 'credential': event['certificateSha256'],
                'operationCredential': event['session'], 'channelBindingSha256': event['channelBindingSha256'],
                'client': event['remote'], 'server': event['local'], 'revokedAtAuthentication': event['revoked'], 'observation': source}
            sessions.append(session); active[event['session']] = session
            projected.append(dict(event, observation=source))
        elif kind == 'operation':
            session = active.get(event['session'])
            require(session is not None and session['authenticationOrder'] < event['order'] and
                    session['person'] == event['person'] and session['credential'] == event['certificateSha256'] and
                    session['client'] == event['remote'] and session['server'] == event['local'], 'Operation lacks its preceding authenticated channel')
            account = next(a for a in accounts if a['person'] == event['person'])
            allowed = event['certificateSha256'] not in revoked and (event['path'] == '/status' or
                (event['path'] == '/filter' and account['role'] == 'SecurityAdministrator'))
            require(event['status'] == (200 if allowed else 403), 'Operation status contradicts actual permission policy')
            require(bytes.fromhex(event['requestHex']).split(b'\r\n')[0] == ('GET ' + event['path'] + ' HTTP/1.1').encode(), 'Request bytes do not match operation')
            attempts.append(dict(event, observation=source, admitted=allowed))
            if allowed:
                projected.append(dict(event, observation=source, operationCredential=session['operationCredential']))
        elif kind == 'connectionClosed':
            require(event['session'] in active, 'Close has no active connection')
            del active[event['session']]
            projected.append(dict(event, observation=source))
        elif kind == 'credentialRevoked':
            require(any(a['certificateSha256'] == event['certificateSha256'] for a in accounts), 'Unknown revoked credential')
            revoked.add(event['certificateSha256']);projected.append(dict(event, observation=source))
        else:
            require(kind in ['ready', 'tlsRejected', 'stopped'], 'Unmodeled lifecycle event')
    require(not active and len(sessions) == 4 and [a['status'] for a in attempts] == [200, 403, 200, 403] and
            len([e for e in events if e['kind'] == 'tlsRejected']) == 1, 'Lifecycle matrix is incomplete')
    observations = [{'id': row['id'], 'record': row} for row in commands] + raw
    report = {'devices': [{'id': 'V31_ADMIN_OUTER'}, {'id': 'V31_ADMIN_AW'}], 'accounts': accounts,
        'sessions': sessions, 'events': projected, 'attempts': attempts,
        'listeners': [{'device': 'V31_ADMIN_OUTER', 'address': '10.32.0.2', 'port': 8443, 'transport': 'tcp', 'service': 'administration', 'sourceSha256': SERVER_HASH}],
        'coverage': [{'scope': SCOPE, 'accountInventory': 'All accounts configured in this service and its two per-user clients.',
            'operationCredentialMeaning': 'Reference to the actual authenticated TLS channel; no application bearer token is issued.',
            'revocationMeaning': 'The service rejects operations after its configured certificate revocation event. TLS certificate verification still succeeds.',
            'missing': ['Real human identity and appointment assurance', 'Organizational CNSA/NIST compliance confirmation'],
            'excluded': ['Other historical deployment services, including ND_O_A1:443', 'Out-of-band worker/root administration']}],
        'observations': observations, 'rawObservationIds': [o['id'] for o in observations], 'manifestSha256': digest,
        'projectionVersion': 'administration-lifecycle-v1', 'scope': [SCOPE, 'TLS/OS implementation and collector truth remain assumptions.']}
    return {'runtime_backend': 'isolated-linux-mtls-administration'}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    rows = [row for row in report['observations'] if row['id'] == observation]
    require(len(rows) == 1, 'Unknown administration observation')
    record = rows[0]['record']
    return record.get('stderr' if stderr else 'stdout', '') if 'command' in record else json.dumps(record, sort_keys=True)


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
