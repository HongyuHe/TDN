import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_physical_partition import parse_worker, generate
from import_os_diversity import parse

BASE = ROOT / "artifacts/snapshots/2026-10-24T014455Z"


class DiversityImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workers = [
            parse_worker(BASE / ("multiworker-" + worker + "-collect-before-v3"),
                         BASE / ("multiworker-" + worker + "-collect-after-v3"),
                         BASE / ("multiworker-" + worker + "-sidecar-bindings-v3") if worker in ["w176", "w008"] else None)
            for worker in ["w159", "w163", "w176", "w008"]
        ]

    def test_complete_role_partition(self):
        source, devices = generate(self.workers)
        self.assertEqual(len(devices), 23)
        self.assertIn("physical_separation_from_disjoint_role_hardware", source)

    def test_duplicate_physical_worker_rejected(self):
        changed = copy.deepcopy(self.workers)
        old = changed[0]["hardware"]
        for device in changed[1]["phases"][0]["devices"].values():
            device["physicalDevice"] = old
        with self.assertRaisesRegex(ValueError, "share physical hardware"):
            generate(changed)

    def test_device_duplicated_across_workers_rejected(self):
        changed = copy.deepcopy(self.workers)
        name, value = next(iter(changed[0]["phases"][0]["devices"].items()))
        changed[1]["phases"][0]["devices"][name] = value
        with self.assertRaisesRegex(ValueError, "multiple workers"):
            generate(changed)

    def test_security_role_omission_rejected(self):
        changed = copy.deepcopy(self.workers)
        for worker in changed:
            worker["phases"][0]["devices"] = {
                name: value for name, value in worker["phases"][0]["devices"].items()
                if value["role"] != "grayFirewall"}
        with self.assertRaisesRegex(ValueError, "omits declared devices"):
            generate(changed)

    def test_role_spread_to_second_hardware_is_allowed(self):
        changed = copy.deepcopy(self.workers)
        values = [value for value in changed[0]["phases"][0]["devices"].values() if value["role"] == "inner"]
        values[0]["physicalDevice"] = "different-hardware"
        source, devices = generate(changed)
        self.assertIn("different-hardware", source)
        self.assertEqual(len(devices), 23)

    def test_partial_role_overlap_rejected(self):
        changed = copy.deepcopy(self.workers)
        values = [value for value in changed[0]["phases"][0]["devices"].values() if value["role"] == "inner"]
        values[0]["physicalDevice"] = changed[1]["hardware"]
        with self.assertRaisesRegex(ValueError, "share physical hardware"):
            generate(changed)

    def test_helper_inventory_is_bound(self):
        count = sum(len(worker["helper_bindings"]["bindings"]) for worker in self.workers if worker["helper_bindings"])
        self.assertEqual(count, 7)
        for worker in self.workers:
            for binding in (worker["helper_bindings"] or {}).get("bindings", []):
                self.assertEqual(binding["helper"]["network_namespace"], binding["parent"]["network_namespace"])
                self.assertEqual(binding["helper"]["network_mode"], "container:" + binding["parent"]["id"])

    def test_observed_os_identity_inventory(self):
        identities = parse(BASE / "freebsd-native-integration-v8", BASE / "native-Outer-OS-bindings-v3")
        self.assertEqual(len(identities), 4)
        self.assertEqual({value["osFamily"] for value in identities.values() if value["role"] == "inner"}, {"FreeBSD"})
        self.assertEqual({value["osFamily"] for value in identities.values() if value["role"] == "outer"}, {"Linux"})


if __name__ == "__main__":
    unittest.main()
