import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts/construction"))
from import_auditor_rotation import parse

BASE = Path("artifacts/snapshots/2026-10-24T014455Z")
DERIVED = Path("artifacts/construction/2026-10-24T014455Z/evidence/derived-auditor-rotation-v1")


class AuditorRotationImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.derived = Path(self.temp.name)/"derived"
        shutil.copytree(DERIVED,self.derived)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, update, rehash=True):
        path=self.derived/"rotation.json"
        data=json.loads(path.read_text())
        update(data)
        path.write_text(json.dumps(data))
        if rehash:
            manifest=json.loads((self.derived/"manifest.json").read_text())
            manifest["files"][0]["sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
            (self.derived/"manifest.json").write_text(json.dumps(manifest))

    def test_raw_bound_actual_prefix(self):
        data=parse(BASE,DERIVED)
        self.assertEqual(len(data["before_read"]),8)
        self.assertEqual(data["listener_process"]["pid"],641)

    def test_self_consistent_changed_prefix_rejected(self):
        self.change(lambda d:d["before_read"].pop())
        with self.assertRaisesRegex(ValueError,"raw observations"):
            parse(BASE,self.derived)

    def test_invented_later_record_rejected(self):
        self.change(lambda d:d["later_observed_active"].append("{}"))
        with self.assertRaisesRegex(ValueError,"raw observations"):
            parse(BASE,self.derived)

    def test_unhashed_derivation_rejected(self):
        self.change(lambda d:d.update(component="OTHER"),False)
        with self.assertRaisesRegex(ValueError,"manifest"):
            parse(BASE,self.derived)

    def test_wrong_deriver_pin_rejected(self):
        path=self.derived/"manifest.json"
        data=json.loads(path.read_text())
        data["deriver_sha256"]="0"*64
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,"source changed"):
            parse(BASE,self.derived)


if __name__ == "__main__":
    unittest.main()
