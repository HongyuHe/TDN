"""Check complete raw placement bindings for the selected screening routers."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_optional_screening import parse


class OptionalScreeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "bundle"
        shutil.copytree(ROOT / "data/snapshots/2026-10-24T014455Z/utility-v4/screen-existing", self.path)

    def tearDown(self):
        self.temp.cleanup()

    def mutate(self, filename, update):
        path = self.path / filename
        data = json.loads(path.read_text())
        update(data)
        path.write_text(json.dumps(data))
        manifest_path = self.path / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        row = next(row for row in manifest["files"] if row["path"] == filename)
        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))

    def test_complete_placement(self):
        data = parse(self.path)
        self.assertEqual(len(data["controls"]), 2)
        self.assertTrue(all(c["locatedOnBlack"] and not c["insideSolutionBoundary"]
                            for c in data["controls"]))

    def test_omitted_link(self):
        self.mutate("evidence.json", lambda d: d["links"].pop())
        with self.assertRaisesRegex(ValueError, "omit or duplicate"):
            parse(self.path)

    def test_wrong_zone(self):
        def update(data):
            next(link for link in data["links"] if "FA:inside" in link["endpoints"])["zone"] = "gray"
        self.mutate("evidence.json", update)
        with self.assertRaisesRegex(ValueError, "Zone"):
            parse(self.path)

    def test_changed_role(self):
        def update(data):
            next(row for row in data["devices"] if row["id"] == "FA")["role"] = "outer"
        self.mutate("evidence.json", update)
        with self.assertRaisesRegex(ValueError, "role inventory"):
            parse(self.path)

    def test_missing_device_observation(self):
        self.mutate("stable-after.json", lambda d: d.pop("FB"))
        with self.assertRaisesRegex(ValueError, "Incomplete observed"):
            parse(self.path)

    def test_normalized_interface_disagrees(self):
        self.mutate("stable-before.json", lambda d: d["FA"]["interfaces"].update(value="[]"))
        with self.assertRaisesRegex(ValueError, "Raw observation"):
            parse(self.path)

    def test_wrong_raw_target(self):
        def update(rows):
            next(row for row in rows if row["id"] == "cmd-0139")["command"][3] = "another-namespace"
        self.mutate("commands.json", update)
        with self.assertRaisesRegex(ValueError, "Raw observation"):
            parse(self.path)

    def test_hidden_down_attachment(self):
        phase = json.loads((self.path / "stable-before.json").read_text())
        record = phase["FA"]["interfaces"]
        rows = json.loads(record["value"])
        rows.append({"ifname": "hidden", "ifindex": 99999, "link_index": 99998,
                     "flags": [], "linkinfo": {"info_kind": "veth"}, "addr_info": []})
        value = json.dumps(rows)
        self.mutate("stable-before.json", lambda d: d["FA"]["interfaces"].update(value=value))
        def update(commands):
            next(row for row in commands if row["id"] == record["observation_id"])["stdout"] = value
        self.mutate("commands.json", update)
        with self.assertRaisesRegex(ValueError, "omit or duplicate"):
            parse(self.path)

    def test_empty_error_is_failure(self):
        self.mutate("evidence.json", lambda d: d.update(error=""))
        with self.assertRaisesRegex(ValueError, "clean collection"):
            parse(self.path)


if __name__ == "__main__":
    unittest.main()
