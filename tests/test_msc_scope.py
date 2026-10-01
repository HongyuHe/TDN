"""Prevent omitted properties, altered quotations, and overstated proof coverage."""

from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RequirementScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "docs/CSfC_network_properties.md").read_text()
        cls.scope = json.loads((ROOT / "models/msc_requirement_scope.json").read_text())
        cls.rows = cls.scope["entries"]
        cls.indexed = {row["id"]: row for row in cls.rows}
        cls.originals = {
            match[1]: match[2].strip()
            for match in re.finditer(
                r"^#{3,4} ((?:MSC-[A-Z]+-\d+|(?:N|ISSUE|DEP)-\d+))[^\n]*\n"
                r"(.*?)(?=^#{1,4} |\Z)",
                cls.source,
                re.M | re.S,
            )
        }

    def test_table_three_category_counts_and_denominators(self):
        spec = importlib.util.spec_from_file_location("msc_docs", ROOT / "scripts/render_msc_property_docs.py")
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        counts = renderer.category_counts(self.scope)
        self.assertEqual([r["code"] for r in counts],
                         ["PS", "SR", "VG", "MD", "AA", "IR", "OR", "PF", "CM", "DM", "MR", "AU", "GD", "RP", "RB", "TR", "KM"])
        self.assertEqual(sum(r["listed"] for r in counts), 214)
        self.assertEqual(sum(r["active"] for r in counts), 194)
        self.assertEqual(sum(r["excluded"] for r in counts), 23)
        self.assertEqual(sum(r["denominator"] for r in counts), 171)
        for row in counts:
            self.assertEqual(row["checked"] + row["unchecked"], row["denominator"])
        summary = renderer.category_summary(self.scope)
        self.assertIn("34/171 (19.9%)", summary)
        self.assertIn("| Coverage (partial) |", summary)
        self.assertNotIn("With checked contribution", summary)
        self.assertNotIn("Without checked contribution", summary)
        self.assertNotIn("Fully established", summary)
        for code in renderer.ANNEX_CATEGORIES:
            line = next(line for line in summary.splitlines() if line.startswith(f"| **{code}**:"))
            self.assertIn("0 represented | N/A | N/A | N/A |", line)
        for path in [renderer.PROVABLE, renderer.UNPROVABLE]:
            self.assertIn(summary, path.read_text())
            self.assertLess(path.read_text().index("## Coverage by Table 3 category"),
                            path.read_text().index("## Selected experiment"))

    def test_every_inventory_entry_has_one_individual_assessment(self):
        self.assertEqual(len(self.rows), 293)
        self.assertEqual(len(self.indexed), len(self.rows))
        self.assertEqual(list(self.indexed), list(self.originals))
        self.assertEqual(
            Counter(identifier.split("-")[0] for identifier in self.indexed),
            {"MSC": 214, "N": 57, "ISSUE": 13, "DEP": 9},
        )
        self.assertFalse(self.scope["full_compliance_proven"])
        for row in self.rows:
            self.assertTrue(row["reason"], row["id"])
            self.assertFalse(row["full_statement_established"], row["id"])
        self.assertEqual(
            Counter(row["source_status"] for row in self.rows if row["id"].startswith("MSC-")),
            {"Active": 194, "Relocated": 15, "Withdrawn": 5},
        )

    def test_source_modality_alternatives_and_status_are_unchanged(self):
        for identifier, body in self.originals.items():
            if not identifier.startswith("MSC-"):
                continue
            row = self.indexed[identifier]
            self.assertEqual(row["source_status"], re.search(r"\*\*Status:\*\* ([^ ·\n]+)", body)[1])
            self.assertEqual(row["modality"], re.search(r"\*\*T/O:\*\* (.*?) ·", body)[1])
            self.assertEqual(row["alternative"], re.search(r"\*\*Alternative:\*\* ([^\n]+)", body)[1])

    def test_each_document_quotes_complete_entries_verbatim(self):
        for name, selected in [
            ("unprovable", list(self.originals)),
            ("provable", [row["id"] for row in self.rows if row["theorems"]]),
        ]:
            doc = (ROOT / f"docs/CSfC_network_{name}_properties.md").read_text()
            matches = list(re.finditer(
                r"<!-- inventory: ([A-Z0-9-]+) -->\n(.*?)\n<!-- /inventory: \1 -->",
                doc, re.S,
            ))
            self.assertEqual([match[1] for match in matches], selected)
            for match in matches:
                lines = match[2].splitlines()
                self.assertTrue(all(line == ">" or line.startswith("> ") for line in lines))
                recovered = "\n".join(line[2:] if line.startswith("> ") else "" for line in lines)
                self.assertEqual(recovered, self.originals[match[1]], match[1])
            self.assertNotRegex(doc, r"(?m)^#{1,4} [PU]\d{2}:")

    def test_existing_theorem_references_and_evidence_resolve(self):
        theorem_names = set()
        for path in (ROOT / "TDN/MSC").glob("*.lean"):
            theorem_names.update(re.findall(r"^theorem (\w+)", path.read_text(), re.M))
        referenced = set()
        for row in self.rows:
            self.assertEqual(bool(row["theorems"]), bool(row["model_claim"]), row["id"])
            self.assertEqual(bool(row["theorems"]), row["disposition"].startswith("Checked"), row["id"])
            self.assertTrue(set(row["theorems"]) <= theorem_names, row["id"])
            referenced.update(row["theorems"])
            for key in row["evidence"]:
                self.assertIn(key, self.scope["evidence_catalog"])
        self.assertEqual(
            theorem_names - referenced,
            {"transport_failure_blocks"} | set(self.scope["excluded_theorems"]),
        )
        for _, path in self.scope["evidence_catalog"].values():
            self.assertTrue((ROOT / path).is_file(), path)

    def test_management_exclusion_preserves_the_data_fabric_and_scopes_claims(self):
        projection = self.scope["assessment_projection"]
        snapshot = json.loads((ROOT / "artifacts/msc-node1-model/snapshot/spec.json").read_text())
        excluded = set(projection["excluded_device_ids"])
        management_devices = {
            device["id"] for device in snapshot["devices"]
            if device["role"] == "admin" or
            (device["role"] == "switch" and device.get("level") == "management")
        }
        self.assertEqual(excluded, management_devices)
        zones = {
            (device["id"], interface["name"]): interface["zone"]
            for device in snapshot["devices"] for interface in device["interfaces"]
        }
        retained = [device for device in snapshot["devices"] if device["id"] not in excluded]
        data_links = []
        for link in snapshot["links"]:
            a, b = link["a"], link["b"]
            zone = zones[(a["device"], a["interface"])]
            self.assertEqual(zone, zones[(b["device"], b["interface"])])
            if zone != "management":
                self.assertNotIn(a["device"], excluded)
                self.assertNotIn(b["device"], excluded)
                data_links.append(link)
        self.assertEqual(len(retained), projection["retained_device_count"])
        self.assertEqual(len(data_links), projection["retained_link_count"])
        self.assertEqual(sum(bool(device.get("tunnel")) for device in retained), 8)
        excluded_rows = [row for row in self.rows if row["assessment_scope"] == "excluded_management"]
        self.assertEqual(len(excluded_rows), 35)
        for row in excluded_rows:
            self.assertEqual(row["disposition"], "Outside experiment: management excluded")
            self.assertEqual(row["theorems"], [])
            self.assertEqual(row["model_claim"], "")
        for row in self.rows:
            self.assertIn(row["assessment_scope"], self.scope["scope_labels"])
            self.assertFalse(set(row["theorems"]) & set(self.scope["excluded_theorems"]))
        self.assertEqual(self.indexed["N-28"]["assessment_scope"], "excluded_management")
        self.assertEqual(self.indexed["MSC-OR-4"]["assessment_scope"], "retained")
        self.assertEqual(self.indexed["N-02"]["assessment_scope"], "retained")

    def test_review_is_bound_to_the_reviewed_inventory_and_pdf(self):
        review = self.scope["review"]
        self.assertEqual(review["inventory_sha256"], hashlib.sha256(self.source.encode()).hexdigest())
        self.assertEqual(review["pdf_sha256"], hashlib.sha256((ROOT / review["pdf"]).read_bytes()).hexdigest())
        comparisons = review["numbered_description_comparison"]
        self.assertEqual([row["id"] for row in comparisons], [key for key in self.originals if key.startswith("MSC-")])
        self.assertEqual(
            [row["id"] for row in comparisons if not row["description_matches_pdf_after_whitespace_normalization"]],
            ["MSC-VG-19"],
        )

    def test_generated_documents_match_the_individual_review(self):
        spec = importlib.util.spec_from_file_location("render_msc_property_docs", ROOT / "scripts/render_msc_property_docs.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        entries = module.inventory_entries(self.source)
        for path, checked in [(module.PROVABLE, True), (module.UNPROVABLE, False)]:
            self.assertEqual(path.read_text(), module.render(self.scope, entries, checked), str(path))

    def test_all_companion_links_target_individual_entries(self):
        documents = {
            name: (ROOT / f"docs/CSfC_network_{name}_properties.md").read_text()
            for name in ["provable", "unprovable"]
        }
        for name, doc in documents.items():
            for target, anchor in re.findall(r"CSfC_network_(provable|unprovable)_properties\.md#([a-z0-9-]+)", doc):
                self.assertIn(f'<a id="{anchor}"></a>', documents[target], (name, target, anchor))


if __name__ == "__main__":
    unittest.main()
