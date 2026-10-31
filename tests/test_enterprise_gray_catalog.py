"""Check table scope, alternative continuations and complete annex row coverage."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from catalog_enterprise_gray import extract, TABLE_COUNTS
from validate_evidence import EvidenceError

SOURCE = ROOT / "data/construction/2026-10-24T014455Z/references/enterprise-gray.indexed.txt"


class EnterpriseGrayCatalogTests(unittest.TestCase):
    def setUp(self):
        self.text = SOURCE.read_text()

    def test_all_tables_and_reused_identifiers(self):
        rows = extract(self.text)
        self.assertEqual(len(rows), sum(TABLE_COUNTS.values()))
        for identity in ["EG-AR-25", "EG-AR-26"]:
            selected = [row for row in rows if row["requirement_id"] == identity]
            self.assertEqual([row["table"] for row in selected], [8, 11])
            self.assertTrue(all(row["id_reused_in_another_table"] for row in selected))
            self.assertNotEqual(selected[0]["source_text"], selected[1]["source_text"])

    def test_alternative_continuations_are_not_extra_rows(self):
        rows = extract(self.text)
        alternative = next(row for row in rows if row["requirement_id"] == "EG-FW-8")
        self.assertIn("EG-FW-10", alternative["source_text"])
        self.assertEqual(sum(row["requirement_id"] == "EG-FW-10" for row in rows), 1)

    def test_missing_row_rejected(self):
        changed = self.text.replace("L790@P29: EG-FW-1 The Gray Firewall must only accept", "L790@P29: omitted")
        with self.assertRaisesRegex(EvidenceError, "coverage changed"):
            extract(changed)

    def test_added_row_rejected(self):
        changed = self.text.replace("L790@P29:", "L789@P29: EG-FW-99 Invented requirement\nL790@P29:")
        with self.assertRaisesRegex(EvidenceError, "coverage changed"):
            extract(changed)

    def test_relocated_rows_stay_visible(self):
        rows = extract(self.text)
        moved = [row for row in rows if row["construction_status"] == "delegated_to_named_key_management_annex"]
        self.assertEqual({row["requirement_id"] for row in moved}, {"EG-AR-12", "EG-AR-13", "EG-AR-14"})


if __name__ == "__main__":
    unittest.main()
