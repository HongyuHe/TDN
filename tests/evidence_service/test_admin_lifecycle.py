"""Validate actual TLS-channel bindings and rejected administration attempts."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from tdn_evidence.admin_lifecycle import parse

FIXTURE = Path(__file__).parent / 'fixtures/admin-lifecycle'


def refresh(root):
    path = root / 'manifest.json'
    manifest = json.loads(path.read_text())
    for row in manifest['files']:
        row['sha256'] = hashlib.sha256((root / row['path']).read_bytes()).hexdigest()
    path.write_text(json.dumps(manifest))


class LifecycleTests(unittest.TestCase):
    def test_actual_lifecycle(self):
        _, report = parse(FIXTURE)
        self.assertEqual(len(report['accounts']), 2)
        self.assertEqual(len(report['sessions']), 4)
        self.assertEqual([row['status'] for row in report['attempts']], [200, 403, 200, 403])
        self.assertEqual(len([e for e in report['events'] if e['kind'] == 'operation']), 2)
        self.assertTrue(all(s['operationCredential'] == s['id'] for s in report['sessions']))

    def test_operation_on_another_channel_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'capture';shutil.copytree(FIXTURE, root)
            path = root / 'server.jsonl'
            records = [json.loads(line) for line in path.read_text().splitlines()]
            next(r for r in records if r['kind'] == 'operation')['session'] = 'unbound'
            path.write_text(''.join(json.dumps(r)+'\n' for r in records));refresh(root)
            with self.assertRaisesRegex(ValueError, 'preceding authenticated channel'):
                parse(root)

    def test_revoked_operation_cannot_be_reported_as_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'capture';shutil.copytree(FIXTURE, root)
            path = root / 'server.jsonl'
            records = [json.loads(line) for line in path.read_text().splitlines()]
            [r for r in records if r['kind'] == 'operation'][-1]['status'] = 200
            path.write_text(''.join(json.dumps(r)+'\n' for r in records));refresh(root)
            with self.assertRaisesRegex(ValueError, 'permission policy'):
                parse(root)

    def test_changed_service_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'capture';shutil.copytree(FIXTURE, root)
            path = root / 'server.py';path.write_text(path.read_text().replace('status=200 if accepted else 403','status=200'))
            refresh(root)
            with self.assertRaisesRegex(ValueError, 'Unreviewed administration'):
                parse(root)


if __name__ == '__main__':
    unittest.main()
