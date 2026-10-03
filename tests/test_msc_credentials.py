"""Exercise evidence retention and consistency across public credential views."""

import copy
import json
import re
import unittest

from scripts import import_msc_snapshot as importer
from scripts import msc_credentials as parser


class CredentialEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        status = json.loads((importer.CURRENT_EVIDENCE / 'snapshot/status.json').read_text())
        cls.facts = next(d['facts'] for d in status['devices'] if d['device'] == 'I_A1')

    def test_every_public_object_is_retained_and_verified(self):
        f = self.facts
        audit = parser.parse_audit(f['credential-audit'], f['certificate-pem'], f['trusted-ca-pem'])
        self.assertEqual((len(audit['certificates']), len(audit['crls'])), (3, 1))
        self.assertTrue(all(v['valid'] for c in audit['certificates'] + audit['crls'] for v in c['verifications']))
        for c in audit['certificates']:
            self.assertEqual((c['publicKeyAlgorithm'], c['publicKeyBits'], c['curve']), ('ECDSA', 384, 'P-384'))
            self.assertLess(c['notBefore'], audit['atEpoch'])
            self.assertGreater(c['notAfter'], audit['atEpoch'])

    def test_public_text_mutations_remain_visible(self):
        original = importer.parse_public_certificates(self.facts['certificates'], 'I_A1')
        for before, after in [('ECDSA 384 bits', 'RSA 512 bits'), ('Oct 27', 'Sep 27'),
                              ('serverAuth clientAuth', 'clientAuth'), (', ok', ', expired')]:
            text = self.facts['certificates'].replace(before, after)
            self.assertNotEqual(importer.parse_public_certificates(text, 'I_A1'), original)

    def test_public_object_hash_and_inventory_cannot_be_faked_by_omission(self):
        f = self.facts
        original = json.loads(f['credential-audit'])
        for mutate in [lambda a: a['certificates'].pop(), lambda a: a['crls'].clear(),
                       lambda a: a.update(pem_sha256='0'*64), lambda a: a['anchors'].clear()]:
            audit = copy.deepcopy(original)
            mutate(audit)
            with self.assertRaises(ValueError):
                parser.parse_audit(json.dumps(audit), f['certificate-pem'], f['trusted-ca-pem'])
        with self.assertRaisesRegex(ValueError, 'PEM'):
            parser.pem_fingerprints(f['certificate-pem'] + '-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----')

    def test_reported_crls_keep_dates_revocations_and_missing_inventory(self):
        text = self.facts['certificates']
        original = parser.parse_reported_crls(text)
        self.assertEqual(len(original), 1)
        self.assertEqual(original[0]['revoked'], [])
        changed = text.replace('0 revoked certificates', '1 revoked certificates:\n    ab: Oct 02 22:40:08 UTC 2026, key compromise')
        revoked = parser.parse_reported_crls(changed)[0]['revoked']
        self.assertEqual(revoked[0]['serial'], 'ab')
        self.assertEqual(revoked[0]['reason'], 'key compromise')
        self.assertEqual(parser.parse_reported_crls(text.split('List of X.509 CRLs')[0] + 'List of X.509 CRLs\n'), [])
        with self.assertRaisesRegex(ValueError, 'count'):
            parser.parse_reported_crls(text.replace('0 revoked', '1 revoked'))

    def test_additional_sessions_survive_even_when_one_expected_session_exists(self):
        original = self.facts['sas']
        baseline = parser.parse_sessions(original)
        wrong = re.sub(r': #(\d+),', lambda match: f': #{int(match[1]) + 1000},', original)
        wrong = wrong.replace('I_B1.msc.test', 'I_B2.msc.test')
        sessions = parser.parse_sessions(original + wrong)
        self.assertEqual(len(sessions), 2 * len(baseline))
        self.assertEqual(sessions[len(baseline)]['remoteIdentity'], 'I_B2.msc.test')
        self.assertNotEqual(sessions[0]['uniqueId'], sessions[len(baseline)]['uniqueId'])
        for before, after, field in [('reqid 101', 'reqid 999', 'reqid'),
                                      ('INSTALLED', 'INSTALLING', 'state'),
                                      ('10.1.1.0/24', '10.1.0.0/16', 'localSelectors')]:
            changed = parser.parse_sessions(original.replace(before, after))
            self.assertNotEqual(changed[0]['children'][0][field], sessions[0]['children'][0][field])

    def test_loaded_revocation_and_all_connections_are_preserved(self):
        f = self.facts
        baseline = parser.bind_connection_details(parser.parse_connections(f['connections']), f['connections-raw'])
        self.assertEqual(baseline[0]['revocation'], 'GOOD')
        changed = parser.bind_connection_details(parser.parse_connections(f['connections']), f['connections-raw'].replace('revocation=GOOD', 'revocation=SKIPPED'))
        self.assertEqual(changed[0]['revocation'], 'SKIPPED')
        extra = f['connections'].replace('msc:', 'extra:').replace('I_B1.msc.test', 'I_B2.msc.test')
        self.assertEqual(len(parser.parse_connections(f['connections'] + extra)), 2)
        with self.assertRaisesRegex(ValueError, 'counts'):
            parser.bind_connection_details(parser.parse_connections(f['connections'] + extra), f['connections-raw'])

    def test_unknown_authentication_constraints_are_rejected(self):
        f = self.facts
        for raw in [f['connections-raw'].replace('groups=[]', 'groups=[new-group]'),
                    f['connections-raw'].replace('revocation=GOOD', 'revocation=GOOD unknown=accept')]:
            with self.assertRaises(ValueError):
                parser.bind_connection_details(parser.parse_connections(f['connections']), raw)
        with self.assertRaises(ValueError):
            parser.parse_sessions(f['sas'] + '\nunknown session metadata\n')

    def test_retrieval_metadata_distinguishes_observed_empty_from_missing(self):
        f = self.facts
        raw = json.loads(f['credential-audit'])
        audited = parser.parse_audit(json.dumps(raw), f['certificate-pem'], f['trusted-ca-pem'])
        self.assertTrue(all(c['crlDistributionPoints'] == [] and c['ocspServers'] == [] and
                            c['issuingCertificateURLs'] == [] for c in audited['certificates']))
        raw['certificates'][0]['ocsp_servers'] = ['http://ocsp.example.test/check']
        changed = parser.parse_audit(json.dumps(raw), f['certificate-pem'], f['trusted-ca-pem'])
        self.assertEqual(changed['certificates'][0]['ocspServers'], ['http://ocsp.example.test/check'])
        for c in raw['certificates']:
            for key in ['crl_distribution_points', 'ocsp_servers', 'issuing_certificate_urls']:
                del c[key]
        missing = parser.parse_audit(json.dumps(raw), f['certificate-pem'], f['trusted-ca-pem'])
        self.assertTrue(all(c['ocspServers'] is None for c in missing['certificates']))

    def test_loaded_authority_inventory_requires_completion_and_retains_uris(self):
        self.assertEqual(parser.parse_authorities(self.facts['authorities-raw']), [])
        event = ('list-authority event {remote {cacert=CN=fixture '
                 'crl_uris=[http://crl.example.test/a ldap://directory.example.test/b] '
                 'ocsp_uris=[http://ocsp.example.test/check] cert_uri_base=http://ca.example.test/}}\n')
        result = parser.parse_authorities(event + 'list-authorities reply {}\n')
        self.assertEqual(result[0]['crlURIs'], ['http://crl.example.test/a', 'ldap://directory.example.test/b'])
        self.assertEqual(result[0]['ocspURIs'], ['http://ocsp.example.test/check'])
        self.assertEqual(result[0]['certificateURIBase'], 'http://ca.example.test/')
        for invalid in ['', event, 'list-authorities reply {}\nlist-authorities reply {}\n']:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parser.parse_authorities(invalid)

    def test_service_configuration_keeps_required_fields_and_projects_management(self):
        path = importer.CURRENT_EVIDENCE / 'snapshot/devices/I_A1/intended.services.json'
        raw = json.loads(path.read_text())
        baseline = parser.parse_service_configuration(json.dumps(raw), 'I_A1')
        raw['management'] = {'unavailable': True}
        self.assertEqual(parser.parse_service_configuration(json.dumps(raw), 'I_A1'), baseline)
        raw['revocation_delivery'] = 'remote CRL server'
        self.assertNotEqual(parser.parse_service_configuration(json.dumps(raw), 'I_A1'), baseline)
        del raw['clock']
        with self.assertRaises(ValueError):
            parser.parse_service_configuration(json.dumps(raw), 'I_A1')


if __name__ == '__main__':
    unittest.main()
