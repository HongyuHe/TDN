import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("macsec_boundary_records", ROOT / "scripts/construction/macsec_boundary_records.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PhysicalBoundaryRecordsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = json.loads((ROOT / "data/evidence/continuation/BoundaryMACsec.json").read_text())["rawBundle"]

    def test_three_cases_preserve_payload_and_distinct_physical_results(self):
        result = MODULE.prepare(self.bundle, "test-source")
        protected = result["protected"]
        allowed = result["unprotectedAllowed"]
        denied = result["unprotectedDenied"]
        self.assertEqual(protected["sourceCase"]["application"], allowed["sourceCase"]["application"])
        self.assertEqual(allowed["sourceCase"]["application"], denied["sourceCase"]["application"])
        self.assertEqual(protected["physicalFrame"]["header"]["etherType"], 35045)
        self.assertEqual(allowed["physicalFrame"]["header"]["etherType"], 2048)
        self.assertFalse(allowed["macIfaces"][0]["settings"]["protectFrames"])
        self.assertEqual(allowed["linkPolicies"][0][1]["outbound"]["rules"][1]["verdict"], "allow")
        self.assertEqual(denied["linkPolicies"][0][1]["outbound"]["rules"][1]["verdict"], "deny")
        self.assertIn("no physical wire emission claimed", result["unprotected-deniedProvenance"]["physicalFrameOrigin"])
        self.assertEqual(result["rawBundle"], self.bundle)

    def test_altered_physical_pair_is_rejected(self):
        altered = copy.deepcopy(self.bundle)
        target = altered["cases"][0]["physicalFramePairs"][0]["receive"]
        next(item for item in altered["frames"] if item["id"] == target)["bytes"] = "00"
        with self.assertRaisesRegex(ValueError, "physical frame identity"):
            MODULE.prepare(altered, "altered")

    def test_changed_parent_binding_is_rejected(self):
        altered = copy.deepcopy(self.bundle)
        altered["macsec_ports"][0]["physicalIndex"] += 1
        with self.assertRaisesRegex(ValueError, "physical parent"):
            MODULE.prepare(altered, "altered")

    def test_changed_forwarding_hop_is_rejected(self):
        altered = copy.deepcopy(self.bundle)
        target = altered["cases"][0]["logicalTransmitFrames"][0]
        next(item for item in altered["frames"] if item["id"] == target)["ipv4"]["ttl"] = 64
        with self.assertRaisesRegex(ValueError, "TTL mismatch"):
            MODULE.prepare(altered, "altered")


if __name__ == "__main__":
    unittest.main()
