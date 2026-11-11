import gzip
import hashlib
import json
from pathlib import Path
import shutil
import ssl
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'mcp'))
from tdn_evidence.native_authentication_services import parse

SOURCE = ROOT / 'data/snapshots/2026-11-04-mtu-cohorts/baseline-red-cohort-001/keys-before'


class NativeAuthenticationServicesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / 'capture'
        shutil.copytree(SOURCE, self.bundle, ignore=shutil.ignore_patterns('observations.json'))
        retained = ROOT / 'data/snapshots/2026-11-04-mtu-cohorts'
        index = json.loads((retained / 'compressed-files.json').read_text())
        entry = next(row for row in index['files'] if row['path'] ==
                     'baseline-red-cohort-001/keys-before/observations.json')
        packed = (retained / entry['compressed']).read_bytes()
        self.assertEqual(hashlib.sha256(packed).hexdigest(), entry['compressed_sha256'])
        decoded = gzip.decompress(packed)
        self.assertEqual(hashlib.sha256(decoded).hexdigest(), entry['sha256'])
        (self.bundle / 'observations.json').write_bytes(decoded)
        self.rows = json.loads((self.bundle / 'observations.json').read_text())
        self.capture = json.loads((self.bundle / 'correlation.json').read_text())
        self.first = self.capture['phases'][0]['devices'][0]['id']

    def tearDown(self):
        self.temp.cleanup()

    def row(self, kind, device=None, phase=0):
        record = next(d for d in self.capture['phases'][phase]['devices'] if d['id'] == (device or self.first))
        return next(r for r in self.rows if r['id'] == record['observations'][kind])

    def save(self):
        (self.bundle / 'observations.json').write_text(json.dumps(self.rows))
        (self.bundle / 'correlation.json').write_text(json.dumps(self.capture))
        manifest = json.loads((self.bundle / 'manifest.json').read_text())
        for entry in manifest['files']:
            path = self.bundle / entry['path']
            entry['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            entry['bytes'] = path.stat().st_size
        (self.bundle / 'manifest.json').write_text(json.dumps(manifest))

    def test_complete_bound_public_authorities(self):
        _, report = parse(self.bundle)
        self.assertEqual(len(report['devices']), 8)
        self.assertEqual(len(report['authorities']), 3)
        self.assertEqual(len(report['authentication_services']), 16)
        self.assertTrue(all(not a['runningServiceObserved'] for a in report['authorities']))
        for service in report['authentication_services']:
            self.assertEqual(service['localAuth'], 'ecdsa-384-sha384')
            self.assertEqual(service['localCertificate']['authorityKeyIdentifier'],
                             service['authority']['subjectKeyIdentifier'])
            self.assertEqual(service['peerCertificate']['authorityKeyIdentifier'],
                             service['authority']['subjectKeyIdentifier'])
            self.assertIn(service['configObservation'], report['rawObservationIds'])
            self.assertIn(service['saObservation'], report['rawObservationIds'])
        first, later = report['authentication_services'][0], report['authentication_services'][8]
        self.assertNotEqual(first['saObservation'], later['saObservation'])
        self.assertEqual(first['authenticationSAObservation'], later['authenticationSAObservation'])

    def test_different_layer_ca_rejected(self):
        outer = next(d['id'] for d in self.capture['phases'][0]['devices'] if d['role'] == 'outer')
        self.row('caCertificate')['stdout'] = self.row('caCertificate', outer)['stdout']
        self.save()
        with self.assertRaisesRegex(ValueError, 'authority key identifier differs'):
            parse(self.bundle)

    def test_endpoint_certificate_cannot_be_ca(self):
        self.row('caCertificate')['stdout'] = self.row('leafCertificate')['stdout']
        self.save()
        with self.assertRaisesRegex(ValueError, 'not a signing CA'):
            parse(self.bundle)

    def test_trust_file_mismatch_rejected(self):
        self.row('configuration')['stdout'] = self.row('configuration')['stdout'].replace('cacerts = ca.pem', 'cacerts = another.pem')
        self.save()
        with self.assertRaisesRegex(ValueError, 'Certificate/trust selection differs'):
            parse(self.bundle)

    def test_authentication_method_mismatch_rejected(self):
        self.row('configuration')['stdout'] = self.row('configuration')['stdout'].replace('auth = ecdsa-384-sha384', 'auth = psk')
        self.save()
        with self.assertRaisesRegex(ValueError, 'Certificate/trust selection differs'):
            parse(self.bundle)

    def test_loaded_authority_mismatch_rejected(self):
        self.row('connections')['stdout'] = self.row('connections')['stdout'].replace('cacerts=[CN=Twinet MSC inner-s1]', 'cacerts=[CN=Other CA]')
        self.save()
        with self.assertRaisesRegex(ValueError, 'Loaded authentication or trust reference differs'):
            parse(self.bundle)

    def test_wrong_ca_capture_command_rejected(self):
        self.row('caCertificate')['command'][-1] = '/unrelated/ca.pem'
        self.save()
        with self.assertRaisesRegex(ValueError, 'not bound to its command and device'):
            parse(self.bundle)

    def test_extra_authentication_alternative_rejected(self):
        row = self.row('configuration')
        row['stdout'] = row['stdout'].replace('  children {', '  local2 {\n   auth = psk\n  }\n  children {')
        self.save()
        with self.assertRaisesRegex(ValueError, 'Unsupported configured authentication alternatives'):
            parse(self.bundle)

    def test_second_phase_ike_session_change_rejected(self):
        row = self.row('sas', phase=1)
        row['stdout'] = row['stdout'].replace('uniqueid=', 'uniqueid=9', 1)
        self.save()
        with self.assertRaisesRegex(ValueError, 'Authentication session changed'):
            parse(self.bundle)

    def test_invalid_ca_signature_rejected(self):
        row = self.row('caCertificate')
        der = bytearray(ssl.PEM_cert_to_DER_cert(row['stdout']))
        der[-1] ^= 1
        row['stdout'] = ssl.DER_cert_to_PEM_cert(bytes(der))
        self.save()
        with self.assertRaisesRegex(ValueError, 'certificate signature'):
            parse(self.bundle)

    def test_multiple_ca_chain_requires_explicit_support(self):
        row = self.row('caCertificate')
        row['stdout'] += row['stdout']
        self.save()
        with self.assertRaisesRegex(ValueError, 'one public PEM certificate'):
            parse(self.bundle)

    def test_manifest_tamper_rejected(self):
        self.row('configuration')['stdout'] += '\n'
        (self.bundle / 'observations.json').write_text(json.dumps(self.rows))
        with self.assertRaises(ValueError):
            parse(self.bundle)


if __name__ == '__main__':
    unittest.main()
