"""Mutate retained nft data locally without any device or packet operations."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from native_nft_correspondence import check_native_nft, check_ruleset, read_observation
from validate_evidence import EvidenceError

BUNDLE = ROOT / "artifacts/snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1"


class NativeNftTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads((BUNDLE / "snapshot.json").read_text())
        self.observation = next(o for o in self.snapshot["observations"] if o["kind"] == "nft-hooks")
        self.objects = read_observation(BUNDLE, self.observation)
        self.chains = [c for c in self.snapshot["filters"] if c["device_id"] == "NF_BLACK"]

    def test_complete_shared_and_baseline(self):
        result = check_native_nft(BUNDLE, self.snapshot)
        self.assertEqual(len(result["devices"]), 31)
        baseline = BUNDLE.parent / "native-baseline-20261024T015000Z"
        self.assertEqual(len(check_native_nft(baseline, json.loads((baseline / "snapshot.json").read_text()))["devices"]), 23)

    def test_implicit_empty_ipv6_accept_is_exact(self):
        result = check_ruleset(self.objects, self.chains)
        self.assertEqual(len(result["implicit_empty_accept_chains"]), 3)

    def test_missing_default_deny_chain_rejected(self):
        self.objects["nftables"] = [x for x in self.objects["nftables"] if not
            ("chain" in x and x["chain"]["name"] == "FORWARD")]
        with self.assertRaises(EvidenceError):
            check_ruleset(self.objects, self.chains)

    def test_missing_rule_rejected(self):
        index = next(i for i,x in enumerate(self.objects["nftables"]) if "rule" in x)
        self.objects["nftables"].pop(index)
        with self.assertRaisesRegex(EvidenceError, "rule count"):
            check_ruleset(self.objects, self.chains)

    def test_changed_source_condition_rejected(self):
        for item in self.objects["nftables"]:
            if "rule" not in item:
                continue
            for expr in item["rule"]["expr"]:
                if expr.get("match", {}).get("left") == {"payload": {"protocol": "ip", "field": "saddr"}}:
                    expr["match"]["right"] = "203.0.113.9"
                    with self.assertRaisesRegex(EvidenceError, "conditions differ"):
                        check_ruleset(self.objects, self.chains)
                    return
        self.fail("Missing fixture source rule")

    def test_extra_prerouting_hook_rejected(self):
        self.objects["nftables"].append({"chain": {"family": "ip", "table": "filter",
            "name": "EARLY", "type": "filter", "hook": "prerouting", "prio": -450, "policy": "accept"}})
        with self.assertRaisesRegex(EvidenceError, "hook"):
            check_ruleset(self.objects, self.chains)

    def test_extra_table_rejected(self):
        self.objects["nftables"].append({"table": {"family": "ip", "name": "unmodeled"}})
        with self.assertRaisesRegex(EvidenceError, "table inventory"):
            check_ruleset(self.objects, self.chains)

    def test_rule_order_rejected(self):
        indices = [i for i,x in enumerate(self.objects["nftables"]) if "rule" in x and x["rule"]["chain"] == "INPUT"]
        a,b = indices[:2]
        self.objects["nftables"][a],self.objects["nftables"][b] = self.objects["nftables"][b],self.objects["nftables"][a]
        with self.assertRaisesRegex(EvidenceError, "conditions differ"):
            check_ruleset(self.objects, self.chains)

    def test_wrong_namespace_pid_rejected(self):
        self.observation["command"][2] = "999999999"
        with self.assertRaisesRegex(EvidenceError, "PID"):
            check_native_nft(BUNDLE, self.snapshot)

    def test_duplicate_namespace_pid_rejected(self):
        hooks = [o for o in self.snapshot["observations"] if o["kind"] == "nft-hooks"]
        hooks[1]["command"][2] = hooks[0]["command"][2]
        with self.assertRaises(EvidenceError):
            check_native_nft(BUNDLE, self.snapshot)

    def test_failed_nft_observation_rejected(self):
        self.observation["returncode"] = 1
        with self.assertRaisesRegex(EvidenceError, "Unsuccessful"):
            check_native_nft(BUNDLE, self.snapshot)

    def test_incomplete_nft_inventory_rejected(self):
        self.snapshot["observations"].remove(self.observation)
        with self.assertRaisesRegex(EvidenceError, "Incomplete"):
            check_native_nft(BUNDLE, self.snapshot)


if __name__ == "__main__":
    unittest.main()
