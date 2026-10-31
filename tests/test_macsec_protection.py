"""Reject changed final delay-protection observations and incomplete useful controls."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_macsec_protection import parse

BASE = ROOT / "artifacts/snapshots/2026-10-24T014455Z"


class MACsecProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.case = Path(self.temp.name) / "case"
        shutil.copytree(BASE / "eap-tls-forward-v18", self.case)

    def tearDown(self):
        self.temp.cleanup()

    def run_import(self):
        return parse([self.case], BASE / "hostap-kdf-bindings-v4",
                     BASE / "final-hostap-runtime-v4", BASE / "hostap-auth-lowest-pn-v5")

    def write(self, name, data):
        path = self.case / name
        path.write_text(json.dumps(data))
        manifest_path = self.case / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        row = next(row for row in manifest["files"] if row["path"] == name)
        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))

    def mutate_log(self, before, after):
        data = json.loads((self.case / "commands.json").read_text())
        for row in data:
            if row["command"][0] == "cat" and row["command"][-1].endswith("/P0.log"):
                row["stdout"] = row["stdout"].replace(before, after)
        self.write("commands.json", data)

    def test_actual_settings(self):
        data = self.run_import()
        self.assertEqual(len(data["devices"]), 2)
        self.assertEqual(len(data["controls"]), 8)

    def test_wrong_lifetime(self):
        self.mutate_log("lifetime=6000", "lifetime=7000")
        with self.assertRaisesRegex(ValueError, "timer"):
            self.run_import()

    def test_missing_timer_evidence(self):
        self.mutate_log("EVIDENCE delay LPN", "OTHER record LPN")
        with self.assertRaisesRegex(ValueError, "timer"):
            self.run_import()

    def test_delay_protection_disabled(self):
        self.mutate_log("Delay Protect....: Yes", "Delay Protect....: No")
        with self.assertRaisesRegex(ValueError, "advertised"):
            self.run_import()

    def test_missing_receive_update(self):
        self.mutate_log("set_receive_lowest_pn", "unused_receive_callback")
        with self.assertRaisesRegex(ValueError, "callback"):
            self.run_import()

    def test_missing_reverse_control(self):
        data = json.loads((self.case / "evidence.json").read_text())
        data["probes"].pop()
        self.write("evidence.json", data)
        with self.assertRaisesRegex(ValueError, "bidirectional"):
            self.run_import()

    def test_wrong_control_target(self):
        evidence = json.loads((self.case / "evidence.json").read_text())
        identity = evidence["probes"][0]["observation_id"]
        data = json.loads((self.case / "commands.json").read_text())
        row = next(row for row in data if row["id"] == identity)
        row["command"][3] = "unrelated"
        self.write("commands.json", data)
        with self.assertRaisesRegex(ValueError, "Control command"):
            self.run_import()


if __name__ == "__main__":
    unittest.main()
