"""Check cover settings and failed-send accounting from retained source records."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from tdn_evidence.cover import parse

FIXTURE = Path(__file__).parent / 'fixtures/cover-sender'


def refresh(root):
    path=root/'manifest.json';data=json.loads(path.read_text())
    for row in data['files']:row['sha256']=hashlib.sha256((root/row['path']).read_bytes()).hexdigest()
    path.write_text(json.dumps(data))


class CoverTests(unittest.TestCase):
    def test_failed_sends_remain_explicit(self):
        _,report=parse(FIXTURE)
        self.assertEqual(len(report['configurations']),2)
        self.assertEqual(report['configurations'][0]['statistics']['send_errors'],155)
        self.assertEqual(report['configurations'][0]['maxPayloadBytes'],488)
        self.assertEqual(len(report['attempts']),2827)

    def test_ready_configuration_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'capture';shutil.copytree(FIXTURE,root)
            p=root/'OA-ready.json';d=json.loads(p.read_text());d['interval_ms']=10;p.write_text(json.dumps(d));refresh(root)
            with self.assertRaisesRegex(ValueError,'settings differ'):parse(root)

    def test_missing_attempt_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'capture';shutil.copytree(FIXTURE,root)
            p=root/'OA-cover-events.json';d=json.loads(p.read_text());d['send_events'].pop();p.write_text(json.dumps(d));refresh(root)
            with self.assertRaisesRegex(ValueError,'account for all attempts'):parse(root)


if __name__=='__main__':unittest.main()
