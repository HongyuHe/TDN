import json
import unittest

from cohort import NETWORKS
from freeze_protocol import source_rows
from observe_controls import HERE
from run_series import plan
from score_trials import KNOWN_TYPES, type_verdict


class CohortScoreTests(unittest.TestCase):
    def test_each_type_runs_on_the_three_multilevel_networks(self):
        self.assertEqual(NETWORKS, ("net-03", "net-04", "net-05"))
        self.assertEqual(set(plan()), {(f, n) for n in NETWORKS for f in KNOWN_TYPES})
        self.assertEqual(len(list(plan())), 33)

    def test_a_type_needs_three_observed_hits(self):
        self.assertEqual(type_verdict(["hit"] * 3), "hit")
        for value, verdict in (
            ("pending", "pending"),
            ("miss", "miss"),
            ("timeout", "miss"),
            ("unevaluable", "unevaluable"),
            ("inapplicable", "inapplicable"),
        ):
            self.assertEqual(type_verdict(["hit", value, "hit"]), verdict)
        self.assertEqual(type_verdict(["hit"] * 2), "pending")
        self.assertFalse(
            any("assigned_credit_networks" in spec for spec in KNOWN_TYPES.values())
        )

    def test_registered_faults_point_to_current_source_clauses(self):
        self.assertEqual(source_rows(), 53)
        branches = json.loads((HERE / "clause_branches.json").read_text())
        for clause, duties in branches.items():
            for duty in duties:
                for family in duty.get("types", []):
                    self.assertIn(clause, KNOWN_TYPES[family]["clause_ids"])
                self.assertLessEqual(set(duty.get("profiles", [])), set(NETWORKS))


if __name__ == "__main__":
    unittest.main()
