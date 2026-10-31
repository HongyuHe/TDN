"""Exercise failures that the retired standalone proofs used to reject."""

import copy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
import check_configuration_records as checks


class ConfigurationRecordTests(unittest.TestCase):
    def test_all_direct_check_groups_are_accounted_for(self):
        scope = json.loads((ROOT / "specs/proof_scope.json").read_text())
        expected = {g["id"] for g in scope["groups"] if g["decision"] == "check"}
        report = checks.evaluate(checks.Records(ROOT))
        actual = {group for result in report["results"] for group in result["groups"]}
        self.assertEqual(actual, expected)
        self.assertTrue(all(r["passed"] for r in report["results"]), report)

    def test_empty_evidence_does_not_pass(self):
        self.assertFalse(checks.all_records([], lambda _: True))
        self.assertFalse(checks.separated_assignments([]))
        self.assertFalse(checks.contiguous([], 0))

    def test_unsupported_cipher_and_unprotected_cbc_fail(self):
        records = checks.Records(ROOT)
        suite = copy.deepcopy(records.get("FreshSharedClassicalIKE", "offered")[0])
        suite["aesBits"] = 128
        self.assertFalse(checks.cnsa1(suite))
        policy = copy.deepcopy(records.get("FreshSharedVPNModes", "policies")[0])
        policy["espProposals"] = [{"mode": "cbc", "hmacIntegrity": False}]
        self.assertFalse(checks.vpn_mode(policy))

    def test_cross_layer_workstation_reuse_fails(self):
        self.assertFalse(checks.separated_assignments([
            {"workstation": "aw", "inner": True}, {"workstation": "aw", "inner": False}]))

    def test_gap_overlap_and_truncated_offload_fail(self):
        records = checks.Records(ROOT)
        batches = records.get("FreshAuditOffload", "beforeRestart")
        total = records.get("FreshAuditOffload", "sourceBytes")
        for offset in [batches[1]["offset"] - 1, batches[1]["offset"] + 1]:
            changed = copy.deepcopy(batches)
            changed[1]["offset"] = offset
            self.assertFalse(checks.contiguous(changed, total))
        self.assertFalse(checks.contiguous(batches[:-1], total))

    def test_broadened_dns_guard_fails(self):
        records = checks.Records(ROOT)
        device = copy.deepcopy(records.get("FreshDNSHardening", "devices")[0])
        device["guards"][0]["verdict"] = "allow"
        self.assertFalse(checks.dns_prefix(device))

    def test_missing_or_overlong_lifetime_fails_in_report(self):
        for values in [[], [0], [28801]]:
            records = checks.Records(ROOT)
            records.get("FreshVPNObservedClauses", "espHardSeconds")
            key = "TDN.Imported.FreshVPNObservedClauses.espHardSeconds"
            records.cache["FreshVPNObservedClauses"][key] = values
            result = next(r for r in checks.evaluate(records)["results"] if "RG-023" in r["groups"])
            self.assertFalse(result["passed"])

    def test_manifest_mismatch_fails(self):
        records = checks.Records(ROOT)
        records.expected["FreshSharedClassicalIKE.json"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "manifest"):
            records.get("FreshSharedClassicalIKE", "offered")

    def test_no_active_import_uses_a_retired_module(self):
        import re
        scope = json.loads((ROOT / "specs/proof_scope.json").read_text())
        retired = set(scope["retired_modules"])
        for path in [ROOT / "TDN.lean", *ROOT.joinpath("TDN").rglob("*.lean"),
                     *ROOT.joinpath("tests").rglob("*.lean")]:
            for name in re.findall(r"^import (TDN[\w.]*)", path.read_text(), re.M):
                self.assertNotIn(name, retired, str(path))
                self.assertTrue((ROOT / (name.replace(".", "/") + ".lean")).is_file(), name)

    def test_scope_claims_and_layering_remain_consistent(self):
        import re
        scope = json.loads((ROOT / "specs/proof_scope.json").read_text())
        self.assertEqual({g["id"] for g in scope["groups"]}, {f"RG-{i:03}" for i in range(1, 77)})
        expected = {g[field] for g in scope["groups"] if g["decision"] == "formal"
                    for field in ["general", "application"]}
        actual = set(re.findall(r"^#check (\S+)", (ROOT / "tests/ProofScope.lean").read_text(), re.M))
        self.assertEqual(actual, expected)
        for directory, forbidden in [("Semantics", {"Evidence", "Targets"}), ("Targets", {"Evidence"})]:
            for path in ROOT.joinpath("TDN", directory).glob("*.lean"):
                imports = re.findall(r"^import TDN\.(\w+)", path.read_text(), re.M)
                self.assertFalse(set(imports) & forbidden, str(path))


if __name__ == "__main__":
    unittest.main()
