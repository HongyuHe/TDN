import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/construction/evidence'))
from derive_auditor_rotation import derive


class AuditorRotationDerivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        for name in ['role-admin-deploy-v4', 'role-admin-effective-v3', 'role-admin-matrix-v3']:
            shutil.copytree(ROOT / 'data/snapshots/2026-10-24T014455Z' / name, self.base / name)

    def tearDown(self):
        self.temp.cleanup()

    def change_log(self, name, change):
        bundle = self.base / 'role-admin-effective-v3'
        path = bundle / 'observations.json'
        data = json.loads(path.read_text())
        row = next(row for row in data['records'] if row['command'][-1].endswith('/' + name))
        events = [json.loads(line) for line in row['stdout'].splitlines()]
        change(events)
        row['stdout'] = '\n'.join(json.dumps(event) for event in events) + '\n'
        path.write_text(json.dumps(data))
        manifest = json.loads((bundle / 'manifest.json').read_text())
        manifest['files'][0]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        (bundle / 'manifest.json').write_text(json.dumps(manifest))

    def test_actual_readback_survives(self):
        result = derive(self.base)
        archived = sum(result['after_archives'], [])
        self.assertEqual(archived[:8], result['before_read'])
        self.assertEqual(len(archived), 10)
        self.assertEqual(len(result['later_observed_active']), 14)

    def test_changed_archived_record_rejected(self):
        self.change_log('audit-0002.jsonl', lambda events: events[0].update(path='/changed'))
        with self.assertRaisesRegex(ValueError, 'Archived bytes differ'):
            derive(self.base)

    def test_missing_archived_record_rejected(self):
        self.change_log('audit-0002.jsonl', lambda events: events.pop())
        with self.assertRaisesRegex(ValueError, 'observation coverage'):
            derive(self.base)

    def test_wrong_rotation_actor_rejected(self):
        self.change_log('audit.jsonl', lambda events: events[0].update(role='SecurityAdministrator'))
        with self.assertRaisesRegex(ValueError, 'recorded Auditor'):
            derive(self.base)

    def test_wrong_intervening_actor_rejected(self):
        self.change_log('audit-0002.jsonl', lambda events: events[-1].update(fingerprint='wrong'))
        with self.assertRaisesRegex(ValueError, 'Intervening records differ'):
            derive(self.base)

    def test_reordered_later_records_rejected(self):
        def reorder(events):
            events[1], events[2] = events[2], events[1]
        self.change_log('audit.jsonl', reorder)
        with self.assertRaisesRegex(ValueError, 'chronology changed'):
            derive(self.base)


if __name__ == '__main__':
    unittest.main()
