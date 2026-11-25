import json
import unittest

from freeze_protocol import source_rows
from observe_controls import HERE
from score_trials import KNOWN_TYPES, type_verdict


class FourNetworkScoreTests(unittest.TestCase):
    def test_one_miss_settles_type(self):
        self.assertEqual(type_verdict(["hit", "miss", "pending", "pending"]), "miss")

    def test_all_four_networks_must_receive_credit(self):
        self.assertEqual(type_verdict(["hit"] * 4), "hit")
        self.assertEqual(type_verdict(["hit"] * 3), "pending")
        self.assertEqual(type_verdict(["hit"] * 3 + ["pending"]), "pending")

    def test_a_timed_out_audit_receives_no_detection_credit(self):
        self.assertEqual(type_verdict(["hit", "timeout", "hit", "hit"]), "miss")

    def test_inactive_profile_excludes_four_network_score(self):
        self.assertEqual(
            type_verdict(["inapplicable", "hit", "hit", "hit"]), "inapplicable"
        )
        self.assertEqual(
            type_verdict(["inapplicable", "miss", "hit", "hit"]), "inapplicable"
        )

    def test_gray_firewall_credit_requires_detections_on_the_three_other_networks(self):
        assigned = [
            (name, network) for name, spec in KNOWN_TYPES.items()
            for network in spec.get("assigned_credit_networks", ())
        ]
        self.assertEqual(assigned, [("gray-eligible-deny", "net-02")])
        self.assertEqual(type_verdict(["assigned_credit", "hit", "hit", "hit"]), "hit")
        self.assertEqual(type_verdict(["assigned_credit", "hit", "hit", "miss"]), "miss")
        self.assertEqual(type_verdict(["assigned_credit", "hit", "hit", "pending"]), "pending")

    def test_failed_evidence_collection_is_not_a_miss(self):
        self.assertEqual(
            type_verdict(["unevaluable", "hit", "hit", "hit"]), "unevaluable"
        )

    def test_scope_is_aligned_with_the_current_source_guide(self):
        self.assertEqual(source_rows(), 53)
        scope = json.loads((HERE / "clause_scope.json").read_text())
        parts = json.loads((HERE / "clause_branches.json").read_text())
        for cid, duties in parts.items():
            self.assertIn(cid, scope)
            for duty in duties:
                for family in duty.get("types", []):
                    self.assertIn(cid, KNOWN_TYPES[family]["clause_ids"])
        for index in range(1, 8):
            self.assertEqual(
                scope[f"RG-040.{index:02d}"]["scope"]["net-02"], "inapplicable"
            )


if __name__ == "__main__":
    unittest.main()
