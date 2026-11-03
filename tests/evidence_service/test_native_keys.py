"""Validate active native association correspondence and reject false bindings."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tdn_evidence.native_keys import parse
from tdn_evidence.service import EvidenceService


CAPTURE = Path(__file__).parent / 'fixtures/native-ipsec'


class NativeKeyTests(unittest.TestCase):
    def changed(self, change):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'capture'
            shutil.copytree(CAPTURE, directory)
            correlation = json.loads((directory / 'correlation.json').read_text())
            observations = json.loads((directory / 'observations.json').read_text())
            change(correlation, observations)
            (directory / 'correlation.json').write_text(json.dumps(correlation))
            (directory / 'observations.json').write_text(json.dumps(observations))
            manifest = json.loads((directory / 'manifest.json').read_text())
            for row in manifest['files']:
                raw = (directory / row['path']).read_bytes()
                row.update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
            (directory / 'manifest.json').write_text(json.dumps(manifest))
            return parse(directory)

    def test_live_native_associations(self):
        _, report = parse(CAPTURE)
        self.assertEqual(len(report['devices']), 8)
        self.assertEqual(len(report['associations']), 16)
        self.assertEqual(len(report['authentication']), 8)
        self.assertEqual(len({b['installationReference'] for b in report['associations']}), 16)
        self.assertTrue(all(b['keyBits'] == 256 and b['saltBytes'] == 4 for b in report['associations']))

    def test_key_mismatch_rejected(self):
        def change(capture, observations):
            capture['phases'][0]['bindings'][0]['materials'][0]['sha256'] = 'a' * 64
        with self.assertRaisesRegex(ValueError, 'peer equality'):
            self.changed(change)

    def test_child_spi_mismatch_rejected(self):
        def change(capture, observations):
            row = next(o for o in observations if o['kind'] == 'sas')
            row['stdout'] = row['stdout'].replace('spi-out=c46964b4', 'spi-out=c46964b5')
        with self.assertRaisesRegex(ValueError, 'establishment record|active CHILD'):
            self.changed(change)

    def test_missing_authentication_rejected(self):
        def change(capture, observations):
            row = next(o for o in observations if o['kind'] == 'ikeLog')
            row['stdout'] = row['stdout'].replace('ECDSA_WITH_SHA384_DER successful', 'ECDSA_WITH_SHA384_DER failed')
        with self.assertRaisesRegex(ValueError, 'authentication/CHILD'):
            self.changed(change)

    def test_changed_installation_time_rejected(self):
        def change(capture, observations):
            record = capture['phases'][1]['devices'][0]
            row = next(o for o in observations if o['id'] == record['observations']['statistics'])
            row['stdout'] = row['stdout'].replace('add 2026-11-01 03:00:11', 'add 2026-11-01 03:00:12')
        with self.assertRaisesRegex(ValueError, 'changed between phases'):
            self.changed(change)

    def test_service_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / 'config.json'
            config.write_text(json.dumps({'store': 'store', 'saved_experiments': {
                'native': {'path': str(CAPTURE.resolve()), 'parser': 'native-ipsec-correlation-v1'}}}))
            service = EvidenceService(config)
            try:
                self.assertEqual(service.query_evidence('native', 'associations')['total'], 16)
                exported = service.prepare_lean_bundle('native', 'native_ipsec_keys')
                self.assertEqual(exported, service.prepare_lean_bundle('native', 'native_ipsec_keys'))
            finally:
                service.pool.shutdown(wait=True)


if __name__ == '__main__':
    unittest.main()
