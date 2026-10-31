"""Check that EAP-only claims reject fallback settings and contradictory public logs."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_macsec_key_sources import parse, public_config
from validate_evidence import EvidenceError

BASE = ROOT / "artifacts/snapshots/2026-10-24T014455Z"
SOURCES = ROOT / "artifacts/construction/2026-10-24T014455Z/evidence/runtime/hostap-source"


class KeySourcesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = []
        for name in ["eap-tls-forward-v18", "eap-tls-reverse-v18"]:
            target = Path(self.temp.name) / name
            shutil.copytree(BASE / name, target)
            self.paths.append(target)

    def tearDown(self):
        self.temp.cleanup()

    def run_import(self):
        return parse(self.paths, BASE / "hostap-kdf-bindings-v4", BASE / "final-hostap-runtime-v4", SOURCES)

    def replace_file(self, name, text):
        path = self.paths[0] / name
        path.write_text(text)
        manifest_path = self.paths[0] / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        row = next(row for row in manifest["files"] if row["path"] == name)
        row.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        manifest_path.write_text(json.dumps(manifest))

    def config(self, name):
        return (self.paths[0] / (name + ".conf.public")).read_text()

    def test_actual_four_ports(self):
        data = self.run_import()
        self.assertEqual(len(data["ports"]), 4)
        self.assertTrue(all(not p["settings"]["has_pre_shared_cak"] for p in data["ports"]))
        self.assertFalse(data["whole_RG027_established"])

    def test_added_pre_shared_key_field(self):
        self.replace_file("P0.conf.public", self.config("P0") + "mka_cak=[PUBLIC_TEST_PLACEHOLDER]\n")
        with self.assertRaisesRegex(EvidenceError, "Unreviewed configuration field"):
            self.run_import()

    def test_second_supplicant_network(self):
        text = self.config("P1") + "network={\n}\n"
        with self.assertRaisesRegex(EvidenceError, "Exactly one"):
            public_config(text, "supplicant")

    def test_include_is_not_ignored(self):
        with self.assertRaisesRegex(EvidenceError, "Unreviewed configuration field"):
            public_config(self.config("P0") + "include=more.conf\n", "authenticator")

    def test_control_interface_changes_are_out_of_scope(self):
        with self.assertRaisesRegex(EvidenceError, "Unreviewed configuration field"):
            public_config("ctrl_interface=/run/control\n" + self.config("P1"), "supplicant")

    def test_duplicate_eap_field(self):
        with self.assertRaisesRegex(EvidenceError, "Duplicate"):
            public_config(self.config("P1").replace(" eap=TLS", " eap=TLS\n eap=PEAP"), "supplicant")

    def test_wrong_authentication_mode(self):
        with self.assertRaisesRegex(EvidenceError, "EAP source changed"):
            public_config(self.config("P1").replace("key_mgmt=IEEE8021X", "key_mgmt=NONE"), "supplicant")

    def test_observed_pre_shared_creation(self):
        rows = json.loads((self.paths[0] / "commands.json").read_text())
        row = next(row for row in rows if row["command"][0] == "cat" and
                   Path(row["command"][-1]).name == "P0.log")
        self.assertIn("mode=EAP", row["stdout"])
        row["stdout"] = row["stdout"].replace("mode=EAP", "mode=PSK")
        self.replace_file("commands.json", json.dumps(rows))
        with self.assertRaisesRegex(EvidenceError, "key creation differs"):
            self.run_import()

    def test_missing_creation_log(self):
        rows = json.loads((self.paths[0] / "commands.json").read_text())
        row = next(row for row in rows if row["command"][0] == "cat" and
                   Path(row["command"][-1]).name == "P0.log")
        row["stdout"] = "\n".join(line for line in row["stdout"].splitlines()
                                   if "KaY: Create MKA" not in line)
        self.replace_file("commands.json", json.dumps(rows))
        with self.assertRaisesRegex(EvidenceError, "key creation differs"):
            self.run_import()


if __name__ == "__main__":
    unittest.main()
