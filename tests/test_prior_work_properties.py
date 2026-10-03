"""Check corpus coverage, source fidelity, and important semantic distinctions."""

import importlib.util
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("extract", ROOT / "scripts/extract_prior_work_properties.py")
EXTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXTRACT)


class PriorWorkProperties(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = json.loads((ROOT / "specs/prior_work_network_properties.json").read_text())
        cls.by_path = {d["path"]: d for d in cls.model["datasets"]}

    def test_all_manifest_datasets_and_aliases_are_preserved(self):
        manifest = json.loads((ROOT / "networks/manifest.json").read_text())
        self.assertEqual(len(self.by_path), 312)
        self.assertEqual(set(self.by_path), {d["path"] for d in manifest["datasets"]})
        for d in manifest["datasets"]:
            self.assertEqual(self.by_path[d["path"]]["sources"], d["sources"])
            self.assertTrue((EXTRACT.PAGES / (d["path"] + ".md")).is_file())

    def test_every_saved_scenario_is_preserved_once_per_source(self):
        expected = {}
        for f in (ROOT / "networks").rglob("property*.json"):
            for i, s in enumerate(json.loads(f.read_text())["scenarios"]):
                expected[(str(f.relative_to(ROOT)), f"/scenarios/{i}")] = s
        actual = {}
        for d in self.by_path.values():
            for q in d["queries"]:
                if "recorded_scenario" in q:
                    key = q["source"]["file"], q["source"]["pointer"]
                    self.assertNotIn(key, actual)
                    actual[key] = q["recorded_scenario"]
                    self.assertEqual(q["raw_query"], actual[key]["property"])
                    self.assertEqual(q["validation"], "not rerun")
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 1720)

    def test_congestion_keeps_volumes_and_unresolved_mappings(self):
        qs = self.by_path["sre/exp/mrinfo/AS-3549"]["queries"]
        self.assertEqual(len(qs), 10)
        for q in qs:
            self.assertEqual(q["parsed"]["type"], "Congestion")
            self.assertEqual(len(q["parsed"]["flows"]), 7)
            self.assertEqual(q["parsed"]["threshold"], 500)
            self.assertGreaterEqual(len(q["unresolved"]), 3)
        first = qs[0]["parsed"]["flows"][0]
        self.assertEqual(first, {"source": "67.17.81.225", "destination": "dst0", "volume": 255})

    def test_no_placeholder_is_replaced_by_a_guessed_prefix(self):
        for d in self.by_path.values():
            for q in d["queries"]:
                if "raw_query" in q and "dst: XXX" in q["raw_query"]:
                    self.assertEqual(q["parsed"]["destination"], "XXX")
                    self.assertTrue(any("placeholder XXX" in x for x in q["unresolved"]))

    def test_explicit_probability_and_fixed_links_override_benchmark_defaults(self):
        q = self.by_path["sre/netdice/example"]["queries"][0]
        self.assertEqual(q["parsed"], {"type": "Waypoint", "flow": {"src": "3", "dst": "42.42.0.0/16"}, "waypoint": "4"})
        self.assertEqual(q["failure_model"]["p_link_failure"], 0.1)
        self.assertEqual(len(q["environment"]["links"]["up"]), 4)

    def test_nested_campus_snapshots_do_not_merge_configuration_records(self):
        parent = self.by_path["sre/differential/campus/040412"]["inputs"]
        child = self.by_path["sre/differential/campus/040412/041212"]["inputs"]
        self.assertEqual(parent["configuration_records"], 39)
        self.assertEqual(child["configuration_records"], 28)
        self.assertEqual(len(parent["device_identities"]), 28)
        self.assertFalse(set(parent["configuration_files"]) & set(child["configuration_files"]))

    def test_every_generated_relative_link_resolves(self):
        for p in [EXTRACT.INDEX, *EXTRACT.PAGES.rglob("*.md")]:
            for target in re.findall(r"\]\(<([^>]+)>\)", p.read_text()):
                self.assertTrue((p.parent / target).exists(), f"Broken link in {p}: {target}")

    def test_distinct_isolation_meanings_and_internet2_policy_scope(self):
        c = self.model["catalog"]
        self.assertIn("cannot", c["C2S-I"]["statement"])
        self.assertIn("common links", c["ND-I"]["statement"])
        internet = self.by_path["expresso/internet2"]["catalog_ids"]
        self.assertTrue({"EX-B", "BP-M", "BP-G"}.issubset(internet))
        self.assertNotIn("EX-B", self.by_path["expresso/example"]["catalog_ids"])
        self.assertIn("local BGP RIB", c["BP-M"]["statement"])

    def test_all_query_types_are_recognized(self):
        self.assertEqual(self.model["summary"]["query_types"], {"Waypoint": 1711, "Congestion": 10})
        self.assertEqual(self.by_path["sre/exp/zoo/Kdl"]["queries"], [])

    def test_empty_protocol_fields_are_not_protocol_evidence(self):
        self.assertFalse(EXTRACT.has_nonempty_field({"vrfs": {"default": {"ospfProcesses": {}}}}, {"ospfProcesses"}))
        self.assertTrue(EXTRACT.has_nonempty_field({"vrfs": {"default": {"ospfProcesses": {"1": {}}}}}, {"ospfProcesses"}))
        inp = self.by_path["expresso/internet2"]["inputs"]
        self.assertGreater(len(inp["routing_contexts"]), len(inp["device_identities"]))


if __name__ == "__main__":
    unittest.main()
