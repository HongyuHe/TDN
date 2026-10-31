import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts/construction"))
from import_vpn_observed_clauses import lifetime_rows, parse

BASE = ROOT/"data/snapshots/2026-10-24T014455Z"
BUNDLE = BASE/"native-shared-four-levels-20261024T015300Z-coverage-v1"


class VPNObservedClauseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        snap = json.loads((BUNDLE/"snapshot.json").read_text())
        obs = next(o for o in snap["observations"] if o["device_id"] == "NF_I_A1" and
                   o["command"][-5:] == ["-s", "xfrm", "state", "list", "nokeys"])
        cls.text = json.loads((BUNDLE/obs["raw_path"]).read_text())["stdout"]

    def test_complete_selected_evidence(self):
        report = parse(BUNDLE, BASE/"native-public-auth-bindings-20261024T020200Z")
        self.assertEqual(len(report["certificates"]), 8)
        self.assertEqual(len(report["lifetimes"]), 20)

    def test_actual_positive_hard_limits(self):
        self.assertEqual([r["hard_seconds"] for r in lifetime_rows(self.text)], [3600, 3600])

    def test_disabled_zero_rejected(self):
        with self.assertRaisesRegex(ValueError, "disabled"):
            lifetime_rows(self.text.replace("hard 3600(sec)", "hard 0(sec)"))

    def test_over_eight_hours_rejected(self):
        with self.assertRaisesRegex(ValueError, "eight hours"):
            lifetime_rows(self.text.replace("hard 3600(sec)", "hard 28801(sec)"))

    def test_infinite_limit_rejected(self):
        with self.assertRaisesRegex(ValueError, "hard lifetime"):
            lifetime_rows(self.text.replace("hard 3600(sec)", "hard INF(sec)"))

    def test_use_timer_not_substituted_for_add_timer(self):
        with self.assertRaisesRegex(ValueError, "hard lifetime"):
            lifetime_rows(self.text.replace("expire add:", "expire use:"))

    def test_missing_sa_limit_rejected(self):
        with self.assertRaisesRegex(ValueError, "hard lifetime"):
            lifetime_rows(self.text.replace("hard 3600(sec)", "hard omitted", 1))


if __name__ == "__main__":
    unittest.main()
