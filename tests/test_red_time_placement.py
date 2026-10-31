import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts/construction"))
from import_red_time_placement import parse

BASE = ROOT/"artifacts/snapshots/2026-10-24T014455Z"
CLOCK = BASE/"independent-Red-clocks-v3"
SETUP = BASE/"freebsd-native-integration-v3"


class RedTimePlacementTests(unittest.TestCase):
    def setUp(self):
        self.clock = json.loads((CLOCK/"observations.json").read_text())
        self.setup = json.loads((SETUP/"observations.json").read_text())

    def mutated(self):
        #* Isolate binding checks after the separately tested manifest validator.
        with patch("import_red_time_placement.validate_public_bundle",
                   side_effect=[self.clock, self.setup]):
            return parse(CLOCK, SETUP)

    def test_real_placement(self):
        result = parse(CLOCK, SETUP)
        self.assertEqual(result["inside_bridge"], result["source_bridge"])
        self.assertIn("timed out", result["retained_setup_failure"])

    def test_current_master_mismatch(self):
        row = next(r for r in self.clock["records"] if r["id"] == "diversity-0014")
        value = json.loads(row["stdout"])
        value[0]["master"] = "different"
        row["stdout"] = json.dumps(value)
        with self.assertRaisesRegex(ValueError, "bridge binding"):
            self.mutated()

    def test_guest_mac_mismatch(self):
        row = next(r for r in self.clock["records"] if r["id"] == "diversity-0015")
        row["stdout"] = row["stdout"].replace("02:6f:60:3f:1b:b7", "02:00:00:00:00:00")
        with self.assertRaisesRegex(ValueError, "MAC/address"):
            self.mutated()

    def test_tap_bridge_mismatch(self):
        row = next(r for r in self.setup["records"] if r["id"] == "diversity-0030")
        row["command"][-1] = "different"
        with self.assertRaisesRegex(ValueError, "exact placement"):
            self.mutated()

    def test_wrong_declared_zone(self):
        device = next(d for d in self.setup["spec"]["devices"] if d["id"] == "ND_I_A1")
        next(i for i in device["interfaces"] if i["name"] == "red")["zone"] = "gray"
        with self.assertRaisesRegex(ValueError, "inside-network"):
            self.mutated()

    def test_empty_clock_error_rejected(self):
        self.clock["error"] = ""
        with self.assertRaisesRegex(ValueError, "collection failed"):
            self.mutated()

    def test_empty_setup_error_rejected(self):
        self.setup["error"] = ""
        with self.assertRaisesRegex(ValueError, "Unreviewed setup failure"):
            self.mutated()

    def test_failed_actual_correction_rejected(self):
        row = next(r for r in self.clock["records"] if r["command"][-1:] == ["ntpdate -b -u 10.1.1.20"])
        row["returncode"] = 1
        with self.assertRaisesRegex(ValueError, "actual selected"):
            self.mutated()


if __name__ == "__main__":
    unittest.main()
