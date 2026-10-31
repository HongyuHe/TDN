import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_routing_processes import selected_processes

SOURCE = ROOT / "data/construction/2026-10-24T014455Z/evidence/derived-routing-v3/routing-evidence.json"


class RoutingProcessTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(SOURCE.read_text())

    def test_actual_outer_inventory(self):
        rows = selected_processes(self.data)
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(len(processes) for _, processes in rows), 12)

    def test_added_routing_program_rejected(self):
        device = next(d for d in self.data["configurations"][0]["encryption_devices"] if d["role"] == "outer")
        device["recorded_host_processes"].append(
            {"host_pid": 999999, "name": "bgpd", "command": "/usr/lib/frr/bgpd",
             "recognized_fixed_program": False})
        with self.assertRaisesRegex(ValueError, "Uninterpreted program"):
            selected_processes(self.data)

    def test_empty_process_inventory_rejected(self):
        device = next(d for d in self.data["configurations"][0]["encryption_devices"] if d["role"] == "outer")
        device["recorded_host_processes"] = []
        with self.assertRaisesRegex(ValueError, "Empty process"):
            selected_processes(self.data)

    def test_all_inner_is_not_positive_outer_scope(self):
        for configuration in self.data["configurations"]:
            for device in configuration["encryption_devices"]:
                device["role"] = "inner"
        with self.assertRaisesRegex(ValueError, "No applicable"):
            selected_processes(self.data)

    def test_unknown_command_under_charon_name_rejected(self):
        device = next(d for d in self.data["configurations"][0]["encryption_devices"] if d["role"] == "outer")
        device["recorded_host_processes"][1]["command"] = "/custom/charon"
        with self.assertRaisesRegex(ValueError, "Uninterpreted program"):
            selected_processes(self.data)


if __name__ == "__main__":
    unittest.main()
