"""Keep representative-case work visible after a selected specification is proved."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/construction"))
from refresh_completion_assessment import scope_accounting


class CompletionScopeTests(unittest.TestCase):
    def test_selected_proof_retains_other_cases(self):
        result = scope_accounting({
            "established": True, "completion_certificate": {"scope": "Only current baseline gateways"},
            "remaining_construction_work": [],
            "other_case_application_work": ["Import the CBC and FreeBSD policy cases"]})
        self.assertTrue(result["selected_configuration_established"])
        self.assertEqual(result["selected_scope"], "Only current baseline gateways")
        self.assertEqual(result["all_remaining_work"], ["Import the CBC and FreeBSD policy cases"])
        self.assertFalse(result["all_representative_cases_established"])

    def test_absent_case_queue_does_not_prove_all_cases(self):
        result = scope_accounting({"established": True, "remaining_construction_work": []})
        self.assertFalse(result["all_representative_cases_established"])


if __name__ == "__main__":
    unittest.main()
