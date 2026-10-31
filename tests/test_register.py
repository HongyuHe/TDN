import json
from pathlib import Path
import re
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts/construction"))
from source_paths import output_path
from audit_continuation import without_comments
from register_claim_validation import validate_group_claim
import copy

class RegisterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=Path(__file__).parents[1]
        cls.source=json.loads((cls.root/"artifacts/extraction/requirements/groups.json").read_text())["groups"]
        cls.register=json.loads((output_path("theorem_register.json")).read_text())["groups"]

    def test_all_76_exact_targets(self):
        self.assertEqual(len(self.register),76)
        self.assertEqual([g["group_id"] for g in self.register],[g["group_id"] for g in self.source])
        for original,current in zip(self.source,self.register):
            self.assertEqual(current["original_intended_statement"],original["theorem_statement"])
            self.assertEqual(current["top_level_target"],original["theorem_name"])

    def test_source_conditions_preserved(self):
        for original,current in zip(self.source,self.register):
            self.assertEqual(current["applicability"],original["applicability"])
            self.assertEqual(current["alternatives"],original["alternative_logic_interpretation"])
            self.assertEqual(current["qualifications_and_exceptions"],original["qualifications_and_exceptions"])
            self.assertEqual(current["source_passages"],original["requirement_passages"])
            self.assertEqual([c["source_id"] for c in current["clause_progress"]],[c["source_id"] for c in original["requirement_passages"]])

    def test_current_claims_have_supported_outcomes(self):
        catalog = json.loads(output_path("theorem_register.json").read_text())["evidence_catalog"]
        for group in self.register:
            validate_group_claim(group, catalog)

    def completed_fixture(self):
        return {"established": True, "disposition_reason": "Reviewed selected scope",
                "remaining_construction_work": [], "outstanding_assumptions": [],
                "formal_definition": "TDN.Targets.example_spec", "general_theorem": "TDN.Targets.general_result",
                "clause_progress": [{"source_id": "source-1", "status": "established", "reason": "Checked"}],
                "checked_applications": [{"name": "TDN.Imported.example_result", "whole_group_claim": True}],
                "completion_certificate": {"scope": "fixture", "implementation_contract": "Explicit model",
                    "covered_source_ids": ["source-1"], "evidence_keys": ["snapshot"],
                    "application": {"lean_goal": "TDN.Targets.example_spec TDN.Imported.facts",
                                    "lean_proof": "TDN.Imported.example_result"},
                    "requirement_premises_checked": True}}

    def test_supported_completed_scope_is_permitted(self):
        result = validate_group_claim(self.completed_fixture(), {"snapshot": {}})
        self.assertEqual(result, "example : TDN.Targets.example_spec TDN.Imported.facts := TDN.Imported.example_result")

    def test_incomplete_clause_cannot_be_completed(self):
        value = self.completed_fixture()
        value["clause_progress"][0]["status"] = "construction_in_progress"
        with self.assertRaisesRegex(ValueError, "unfinished source clause"):
            validate_group_claim(value, {"snapshot": {}})

    def test_unrelated_true_goal_cannot_certify_specification(self):
        value = self.completed_fixture()
        value["completion_certificate"]["application"]["lean_goal"] = "True"
        with self.assertRaisesRegex(ValueError, "registered specification"):
            validate_group_claim(value, {"snapshot": {}})

    def test_implication_and_disjunction_cannot_weaken_claim(self):
        for suffix in [" → True", " ∨ True", " -> True", " \\/ True"]:
            value = self.completed_fixture()
            value["completion_certificate"]["application"]["lean_goal"] += suffix
            with self.assertRaisesRegex(ValueError, "named definitions"):
                validate_group_claim(value, {"snapshot": {}})

    def test_unchecked_requirement_or_missing_evidence_is_rejected(self):
        for change in ["requirement_premises_checked", "evidence_keys", "covered_source_ids"]:
            value = copy.deepcopy(self.completed_fixture())
            value["completion_certificate"][change] = False if change == "requirement_premises_checked" else []
            with self.assertRaises(ValueError):
                validate_group_claim(value, {"snapshot": {}})

    def test_unfinished_group_can_record_precise_external_limitation(self):
        validate_group_claim({"established": False, "disposition_reason": "External approval absent",
                              "remaining_construction_work": [],
                              "clause_limitations": [{"source_id": "source-1", "reason": "Authority record absent"}]}, {})

    def test_no_new_axioms_or_placeholder_proofs(self):
        for path in (self.root/"TDN").rglob("*.lean"):
            text=without_comments(path.read_text())
            self.assertIsNone(re.search(r"\b(?:axiom|sorry|admit)\b",text),str(path))

    def test_proof_scan_distinguishes_comments_from_proof_holes(self):
        source = '/- We admit inputs. /- sorry -/ -/\n-- axiom documentation\ndef label := "admit"\ntheorem unfinished : True := by sorry\n'
        clean = without_comments(source)
        self.assertEqual(clean.count("\n"), source.count("\n"))
        self.assertEqual(re.findall(r"\b(?:axiom|sorry|admit)\b", clean), ["sorry"])

if __name__=="__main__":
    unittest.main()
