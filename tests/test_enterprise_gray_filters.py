"""Reject altered device bindings, incomplete chains and unsupported firewall rules."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_enterprise_gray_filters import parse
from validate_evidence import EvidenceError


class EnterpriseGrayFilterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "central-gray-management-v3"
        shutil.copytree(ROOT / "data/snapshots/2026-10-24T014455Z/central-gray-management-v3", self.root)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, filename, update):
        path = self.root / filename
        data = json.loads(path.read_text())
        update(data)
        path.write_text(json.dumps(data))
        manifest_path = self.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        row = next(row for row in manifest["files"] if row["path"] == filename)
        row.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        manifest_path.write_text(json.dumps(manifest))

    def command_change(self, update):
        def transform(rows):
            update(next(row for row in rows if row["id"] == "cmd-0417"))
        self.change("commands.json", transform)

    def coherent_filter_change(self, update):
        phase = "stable-after.json"
        current = json.loads((self.root / phase).read_text())["IA"]["filters4"]["value"]
        replacement = update(current)
        self.change(phase, lambda data: data["IA"]["filters4"].update(value=replacement))
        self.command_change(lambda row: row.update(stdout=replacement))

    def test_retained_observations(self):
        data = parse(self.root)
        self.assertEqual(len(data["records"]), 4)
        self.assertFalse(data["whole_annex_established"])

    def test_changed_device(self):
        self.command_change(lambda row: row.update(device_id="IB"))
        with self.assertRaisesRegex(EvidenceError, "device mismatch"):
            parse(self.root)

    def test_changed_namespace(self):
        self.command_change(lambda row: row["command"].__setitem__(3, "another-device"))
        with self.assertRaisesRegex(EvidenceError, "selected device"):
            parse(self.root)

    def test_failed_capture(self):
        self.command_change(lambda row: row.update(returncode=1))
        with self.assertRaisesRegex(EvidenceError, "successful raw output"):
            parse(self.root)

    def test_additional_table(self):
        self.coherent_filter_change(lambda text: text + "*raw\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n")
        with self.assertRaisesRegex(EvidenceError, "table inventory"):
            parse(self.root)

    def test_extra_input_rule(self):
        self.coherent_filter_change(lambda text: text.replace("COMMIT", "-A INPUT -j DROP\nCOMMIT"))
        with self.assertRaisesRegex(EvidenceError, "INPUT/OUTPUT policy changed"):
            parse(self.root)

    def test_missing_policy_guard(self):
        self.coherent_filter_change(lambda text: text.replace(" -m policy --dir out --pol ipsec --reqid 100", ""))
        with self.assertRaisesRegex(EvidenceError, "Unsupported selected FORWARD rule"):
            parse(self.root)

    def test_missing_phase_device(self):
        self.change("stable-after.json", lambda data: data.pop("DB"))
        with self.assertRaisesRegex(EvidenceError, "inventory incomplete"):
            parse(self.root)


if __name__ == "__main__":
    unittest.main()
