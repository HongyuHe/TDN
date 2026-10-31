import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_macsec_options import parse_case

SOURCE = ROOT / "data/snapshots/2026-10-24T014455Z/macsec-options-v4/xpn256-clear-vlan-2"


class MACsecOptionsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(SOURCE, self.bundle)

    def tearDown(self):
        self.temp.cleanup()

    def read(self, name):
        return json.loads((self.bundle / name).read_text())

    def save(self, name, value):
        (self.bundle / name).write_text(json.dumps(value))
        manifest = self.read("manifest.json")
        for row in manifest["files"]:
            row["sha256"] = hashlib.sha256((self.bundle / row["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def change_interface(self, update, bind=True):
        phase = self.read("before.json")
        observation = phase["A"]["interfaces"]
        rows = json.loads(observation["value"])
        update(rows)
        observation["value"] = json.dumps(rows)
        if bind:
            commands = self.read("commands.json")
            next(c for c in commands if c["id"] == observation["observation_id"])["stdout"] = observation["value"]
            self.save("commands.json", commands)
        self.save("before.json", phase)

    def test_actual_case(self):
        result = parse_case(self.bundle, 2)
        self.assertEqual(len(result["devices"]), 2)
        self.assertTrue(all(d["xpnSupported"] and d["clearVlanSupported"] for d in result["devices"]))

    def test_wrong_raw_binding(self):
        self.change_interface(lambda rows: rows.reverse(), False)
        with self.assertRaisesRegex(ValueError, "raw command"):
            parse_case(self.bundle, 2)

    def test_missing_vlan_layer(self):
        self.change_interface(lambda rows: rows.__setitem__(slice(None), [r for r in rows if r["ifname"] != "vlan1"]))
        with self.assertRaisesRegex(ValueError, "parent chain"):
            parse_case(self.bundle, 2)

    def test_vlan_parent_cycle(self):
        self.change_interface(lambda rows: next(r for r in rows if r["ifname"] == "vlan0").update(link="vlan1"))
        with self.assertRaisesRegex(ValueError, "recorded wire"):
            parse_case(self.bundle, 2)

    def test_non_xpn_cipher(self):
        self.change_interface(lambda rows: next(r for r in rows if r["ifname"] == "macsec0")["linkinfo"]["info_data"].update(cipher_suite="GCM-AES-256"))
        with self.assertRaisesRegex(ValueError, "configuration"):
            parse_case(self.bundle, 2)

    def test_disabled_encryption(self):
        self.change_interface(lambda rows: next(r for r in rows if r["ifname"] == "macsec0")["linkinfo"]["info_data"].update(encrypt=False))
        with self.assertRaisesRegex(ValueError, "configuration"):
            parse_case(self.bundle, 2)

    def test_failed_installation(self):
        commands = self.read("commands.json")
        for c in commands:
            if "gcm-aes-xpn-256" in c["command"]:
                c["returncode"] = 1
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "installation"):
            parse_case(self.bundle, 2)

    def test_probe_wrong_namespace(self):
        evidence = self.read("evidence.json")
        oid = next(p for p in evidence["probes"] if p["expected_result"] == "delivered")["observation_id"]
        commands = self.read("commands.json")
        next(c for c in commands if c["id"] == oid)["command"][3] = "other"
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "peer binding"):
            parse_case(self.bundle, 2)


if __name__ == "__main__":
    unittest.main()
