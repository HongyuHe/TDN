import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_nested_sizing import parse

SOURCE = ROOT / "data/snapshots/2026-10-24T014455Z/MTU-sizing-v3/layers-ipsec-ipsec-integrated"


class NestedSizingTests(unittest.TestCase):
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

    def change(self, phase, device, kind, update, bind=True):
        records = self.read(phase + ".json")
        row = records[device][kind]
        row["value"] = update(row["value"])
        if bind:
            commands = self.read("commands.json")
            next(c for c in commands if c["id"] == row["observation_id"])["stdout"] = row["value"]
            self.save("commands.json", commands)
        self.save(phase + ".json", records)

    def test_actual_nested_geometry(self):
        result = parse(self.bundle)
        self.assertEqual(result["maximum_lengths"], {"red": 1100, "gray": 1156, "black": 1212})
        self.assertEqual(len(result["interfaces"]), 14)
        self.assertFalse(result["whole_RG033_established"])

    def test_missing_device(self):
        data = self.read("evidence.json")
        data["devices"] = [d for d in data["devices"] if d["id"] != "FB"]
        self.save("evidence.json", data)
        with self.assertRaisesRegex(ValueError, "inventory"):
            parse(self.bundle)

    def test_unbound_interface(self):
        self.change("configured-sizing", "IA", "interfaces", lambda s: s.replace('"mtu":1200', '"mtu":1190'), False)
        with self.assertRaisesRegex(ValueError, "raw command"):
            parse(self.bundle)

    def test_insufficient_gray_budget_both_phases(self):
        for phase in ["configured-sizing", "stable-sized-after"]:
            self.change(phase, "IA", "interfaces", lambda s: s.replace('"mtu":1200', '"mtu":1140'))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            parse(self.bundle)

    def test_insufficient_outer_budget_both_phases(self):
        for phase in ["configured-sizing", "stable-sized-after"]:
            self.change(phase, "OA", "interfaces", lambda s: s.replace('"mtu":1400', '"mtu":1200'))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            parse(self.bundle)

    def test_phase_disagreement(self):
        self.change("stable-sized-after", "OA", "interfaces", lambda s: s.replace('"mtu":1400', '"mtu":1300'))
        with self.assertRaisesRegex(ValueError, "changed"):
            parse(self.bundle)

    def test_tfc_padding_requires_new_encoding(self):
        self.change("configured-sizing", "OA", "xfrm", lambda s: s + "\ttfcpad 128\n")
        with self.assertRaisesRegex(ValueError, "length configuration"):
            parse(self.bundle)

    def test_changed_icv_requires_new_encoding(self):
        self.change("configured-sizing", "IA", "xfrm", lambda s: s.replace("<<Keys hidden>> 128", "<<Keys hidden>> 96"))
        with self.assertRaisesRegex(ValueError, "length configuration"):
            parse(self.bundle)

    def test_namespace_mismatch(self):
        commands = self.read("commands.json")
        oid = self.read("configured-sizing.json")["IA"]["interfaces"]["observation_id"]
        next(c for c in commands if c["id"] == oid)["command"][3] = "other"
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "raw command"):
            parse(self.bundle)


if __name__ == "__main__":
    unittest.main()
