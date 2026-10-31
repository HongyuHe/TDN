"""Validate current native topology inventories and declaration bindings."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from analyze_topology import analyze

BASE = ROOT / "artifacts/snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z"
DECLARATION = ROOT / "artifacts/construction/2026-10-24T014455Z/current-topology-scenarios-v1.json"


class FreshTopologyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        shutil.copytree(BASE, self.bundle)
        self.declaration = self.root / "scenario.json"
        shutil.copyfile(DECLARATION, self.declaration)

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self):
        return json.loads((self.bundle / "snapshot.json").read_text())

    def save(self, snapshot=None, manifest=None):
        if snapshot is not None:
            (self.bundle / "snapshot.json").write_text(json.dumps(snapshot))
        if manifest is None:
            manifest = json.loads((self.bundle / "manifest.json").read_text())
        for row in manifest["files"]:
            value = (self.bundle / row["path"]).read_bytes()
            row["sha256"] = hashlib.sha256(value).hexdigest()
            row["bytes"] = len(value)
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))
        declaration = json.loads(self.declaration.read_text())
        for row in declaration["configurations"]:
            if row["configuration_id"] == manifest["configuration_id"]:
                row["snapshot_manifest_sha256"] = hashlib.sha256((self.bundle / "manifest.json").read_bytes()).hexdigest()
        self.declaration.write_text(json.dumps(declaration))

    def run_import(self):
        analyze(self.bundle, self.root / "output.lean", self.root / "report.json",
                scenario_declaration=self.declaration, namespace="MutationTopology")
        return json.loads((self.root / "report.json").read_text())

    def test_fresh_complete_graph(self):
        report = self.run_import()
        self.assertEqual(report["observed_links"], 36)
        self.assertEqual(len(report["gray_connection_paths"]), 4)

    def test_incomplete_inventory(self):
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        manifest["inventory_complete"]["links"]["complete"] = False
        self.save(manifest=manifest)
        with self.assertRaisesRegex(ValueError, "complete observed topology"):
            self.run_import()

    def test_configured_interface(self):
        snapshot = self.snapshot()
        snapshot["interfaces"][0]["status"] = "configured"
        self.save(snapshot)
        with self.assertRaisesRegex(ValueError, "observed topology records"):
            self.run_import()

    def test_wrong_interface_command_namespace(self):
        snapshot = self.snapshot()
        row = next(row for row in snapshot["observations"] if row.get("command", [])[-5:] ==
                   ["ip", "-j", "-d", "address", "show"])
        row["command"][2] = "different-container"
        self.save(snapshot)
        with self.assertRaisesRegex(ValueError, "command target"):
            self.run_import()

    def test_missing_veth_edge(self):
        snapshot = self.snapshot()
        link = next(row for row in snapshot["links"] if row["relation"] == "veth")
        snapshot["links"].remove(link)
        self.save(snapshot)
        with self.assertRaisesRegex(ValueError, "every observed veth"):
            self.run_import()

    def test_changed_declared_zone(self):
        snapshot = self.snapshot()
        interface = next(row for row in snapshot["interfaces"] if row["id"] == "NB_O_A1:gray")
        interface["zone"] = "black"
        self.save(snapshot)
        with self.assertRaisesRegex(ValueError, "zone differs"):
            self.run_import()

    def test_changed_role(self):
        snapshot = self.snapshot()
        next(row for row in snapshot["devices"] if row["id"] == "NB_OF_A1")["role"] = "transport"
        self.save(snapshot)
        with self.assertRaisesRegex(ValueError, "role differs"):
            self.run_import()

    def test_wrong_snapshot_declaration(self):
        value = json.loads(self.declaration.read_text())
        value["configurations"][0]["snapshot_id"] = "another-snapshot"
        self.declaration.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "snapshot/spec binding"):
            self.run_import()


if __name__ == "__main__":
    unittest.main()
