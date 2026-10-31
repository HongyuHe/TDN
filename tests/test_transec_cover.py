"""Reject incomplete or inconsistent retained cover-sender observations."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_transec_cover import parse


class CoverImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(ROOT / "artifacts/snapshots/2026-10-24T014455Z/outer-MACsec-cover-v4", self.bundle)

    def tearDown(self):
        self.temp.cleanup()

    def read(self, name):
        return json.loads((self.bundle / name).read_text())

    def save(self, name, data):
        path = self.bundle / name
        path.write_text(json.dumps(data))
        manifest = self.read("manifest.json")
        row = next(row for row in manifest["files"] if row["path"] == name)
        row.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_retained_successes_and_send_errors(self):
        data = parse(self.bundle)
        self.assertEqual([len(row["events"]) for row in data["endpoints"]], [1411, 1416])
        self.assertEqual([row["stats"]["send_errors"] for row in data["endpoints"]], [155, 0])
        self.assertEqual(len(data["controls"]), 6)

    def test_missing_collection_status(self):
        data = self.read("evidence.json")
        del data["error"]
        self.save("evidence.json", data)
        with self.assertRaisesRegex(ValueError, "explicitly succeed"):
            parse(self.bundle)

    def test_missing_outer(self):
        data = self.read("evidence.json")
        data["devices"] = [row for row in data["devices"] if row["id"] != "OB"]
        self.save("evidence.json", data)
        with self.assertRaisesRegex(ValueError, "inventory"):
            parse(self.bundle)

    def test_changed_record_size(self):
        data = self.read("OA-cover-events.json")
        data["send_events"][10]["body_length"] = 511
        self.save("OA-cover-events.json", data)
        with self.assertRaisesRegex(ValueError, "Record-size"):
            parse(self.bundle)

    def test_missing_attempt(self):
        data = self.read("OA-cover-events.json")
        del data["send_events"][10]
        self.save("OA-cover-events.json", data)
        with self.assertRaisesRegex(ValueError, "sequence"):
            parse(self.bundle)

    def test_incorrect_error_total(self):
        data = self.read("OA-cover-events.json")
        data["stats"]["send_errors"] = 0
        commands = self.read("commands.json")
        row = next(row for row in commands if row["id"] == "cmd-0632")
        row["stdout"] = json.dumps(data["stats"])
        self.save("OA-cover-events.json", data)
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "reconcile"):
            parse(self.bundle)

    def test_changed_launch_arguments(self):
        data = self.read("commands.json")
        row = next(row for row in data if row["id"] == "cmd-0632")
        row["command"].extend(["--interval-ms", "100"])
        self.save("commands.json", data)
        with self.assertRaisesRegex(ValueError, "invocation differs"):
            parse(self.bundle)

    def test_unbound_runtime(self):
        data = self.read("stable-before.json")
        data["OA"]["macsec"]["observation_id"] = data["OB"]["macsec"]["observation_id"]
        self.save("stable-before.json", data)
        with self.assertRaisesRegex(ValueError, "Unbound MACsec"):
            parse(self.bundle)

    def replace_observed_value(self, device, key, change):
        state = self.read("stable-before.json")
        record = state[device][key]
        value = json.loads(record["value"])
        change(value)
        record["value"] = json.dumps(value)
        commands = self.read("commands.json")
        raw = next(row for row in commands if row["id"] == record["observation_id"])
        raw["stdout"] = record["value"]
        self.save("stable-before.json", state)
        self.save("commands.json", commands)

    def test_declared_firewall_peer_does_not_override_raw(self):
        data = self.read("evidence.json")
        for link in data["links"]:
            if "OA:black" in link["endpoints"]:
                link["endpoints"] = ["OA:black", "BF:p2"]
            elif "OB:black" in link["endpoints"]:
                link["endpoints"] = ["OB:black", "BF:p1"]
        self.save("evidence.json", data)
        with self.assertRaisesRegex(ValueError, "Observed peer"):
            parse(self.bundle)

    def test_unrepresented_veth(self):
        def add(rows):
            rows.append({"ifname": "extra", "ifindex": 99999, "linkinfo": {"info_kind": "veth"}})
        self.replace_observed_value("OA", "interfaces", add)
        with self.assertRaisesRegex(ValueError, "omits observed"):
            parse(self.bundle)

    def test_wrong_namespace_peer(self):
        def change(rows):
            next(row for row in rows if row["nsid"] == 2)["name"] = "unrelated-namespace"
        self.replace_observed_value("OA", "peer_nsids", change)
        with self.assertRaisesRegex(ValueError, "Observed peer"):
            parse(self.bundle)

    def test_hardware_offload_needs_another_implementation_contract(self):
        def change(rows):
            next(row for row in rows if row["ifname"] == "macsec0")["linkinfo"]["info_data"]["offload"] = "mac"
        self.replace_observed_value("OA", "interfaces", change)
        with self.assertRaisesRegex(ValueError, "software-path"):
            parse(self.bundle)

    def test_unreviewed_source(self):
        path = self.bundle / "macsec_cover_endpoint_v4.py"
        path.write_text(path.read_text().replace("queue.popleft()", "queue.pop()"))
        manifest = self.read("manifest.json")
        row = next(row for row in manifest["files"] if row["path"] == path.name)
        row.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "Unreviewed sender"):
            parse(self.bundle)


if __name__ == "__main__":
    unittest.main()
