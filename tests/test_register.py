import json
from pathlib import Path
import re
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts/construction"))
from source_paths import output_path

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

    def test_no_unproved_group_claimed_established(self):
        for group in self.register:
            self.assertFalse(group["established"])
            self.assertTrue(group["disposition_reason"])
            self.assertTrue(group["remaining_construction_work"])

    def test_no_new_axioms_or_placeholder_proofs(self):
        for path in (self.root/"TDN").rglob("*.lean"):
            text=path.read_text()
            self.assertIsNone(re.search(r"(?m)^\s*axiom\s|\bsorry\b|\badmit\b",text),str(path))

if __name__=="__main__":
    unittest.main()
