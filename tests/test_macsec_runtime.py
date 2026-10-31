import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_macsec_runtime import parse

SOURCE = ROOT / "data/snapshots/2026-10-24T014455Z/eap-tls-forward-v14"


class MACsecRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(SOURCE, self.bundle)

    def tearDown(self):
        self.temp.cleanup()

    def load(self, name):
        return json.loads((self.bundle / name).read_text())

    def save(self, name, value):
        (self.bundle / name).write_text(json.dumps(value))
        manifest = self.load("manifest.json")
        for row in manifest["files"]:
            row["sha256"] = hashlib.sha256((self.bundle / row["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_real_two_port_case(self):
        self.assertEqual(len(parse(self.bundle)["ports"]), 2)

    def test_unbound_runtime_setting_rejected(self):
        phase = self.load("stable-after.json")
        phase["P0"]["interfaces"]["value"] = phase["P0"]["interfaces"]["value"].replace('"protect":true', '"protect":false')
        self.save("stable-after.json", phase)
        with self.assertRaisesRegex(ValueError, "differs from complete raw"):
            parse(self.bundle)

    def test_observed_unsafe_setting_is_preserved_for_lean_check(self):
        phase = self.load("stable-after.json")
        item = phase["P0"]["interfaces"]
        item["value"] = item["value"].replace('"protect":true', '"protect":false')
        commands = self.load("commands.json")
        next(r for r in commands if r["id"] == item["observation_id"])["stdout"] = item["value"]
        summary = phase["P0"]["macsec"]
        summary["value"] = summary["value"].replace("protect on", "protect off")
        next(r for r in commands if r["id"] == summary["observation_id"])["stdout"] = summary["value"]
        self.save("stable-after.json", phase)
        self.save("commands.json", commands)
        result = parse(self.bundle)
        self.assertFalse(result["ports"][0]["protectFrames"])

    def test_wrong_sci_rejected(self):
        commands = self.load("commands.json")
        for row in commands:
            if row["command"][0] == "cat" and row["command"][-1].endswith("/P0.log"):
                row["stdout"] = row["stdout"].replace("7e:24:26:21:b4:a6::1 (conf_offset", "00:00:00:00:00:00::1 (conf_offset")
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "SCI differs"):
            parse(self.bundle)

    def test_changed_negotiated_group_rejected(self):
        commands = self.load("commands.json")
        for row in commands:
            row["stdout"] = row["stdout"].replace("group=MLKEM1024", "group=P-256")
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "negotiated TLS"):
            parse(self.bundle)

    def test_changed_certificate_key_rejected(self):
        commands = self.load("commands.json")
        for row in commands:
            if row["command"][:2] == ["openssl", "x509"]:
                row["stdout"] = row["stdout"].replace("Public Key Algorithm: ML-DSA-87", "Public Key Algorithm: rsaEncryption")
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "signature/key"):
            parse(self.bundle)

    def test_omitted_peer_rejected(self):
        evidence = self.load("evidence.json")
        evidence["devices"] = [d for d in evidence["devices"] if d["id"] != "P1"]
        self.save("evidence.json", evidence)
        with self.assertRaisesRegex(ValueError, "peer inventory"):
            parse(self.bundle)


if __name__ == "__main__":
    unittest.main()
