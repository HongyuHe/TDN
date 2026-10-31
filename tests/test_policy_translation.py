import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]/"scripts/construction"))
from source_paths import source_path
from import_snapshot import Unsupported, check_installed_policy, guarded, parse_rule, rule_policy_covered, parse_observed_modes

class PolicyTranslationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot=json.loads((source_path("baseline")/"snapshot.json").read_text())
        cls.chain=next(c for c in cls.snapshot["filters"] if c["id"]=="I_A1:filters4:FORWARD")
        cls.tunnel=next(t for t in cls.snapshot["tunnels"] if t["device_id"]=="I_A1")

    def test_all_actual_rules_parse(self):
        for chain in self.snapshot["filters"]:
            for rule in chain["ordered_rules"]:
                parse_rule(rule)

    def test_all_baseline_directional_policies_match(self):
        for tunnel in self.snapshot["tunnels"]:
            self.assertTrue(check_installed_policy(tunnel)["passed"])

    def test_real_forward_guards_covered(self):
        check=check_installed_policy(self.tunnel)
        for raw in self.chain["ordered_rules"]:
            rule=parse_rule(raw)
            self.assertTrue(guarded(rule,"red","gray"))
            self.assertTrue(rule_policy_covered(rule,[check]))

    def test_broadened_allow_rule_fails_guard(self):
        mutant={"ordinal":0,"matches":{"iptables_tokens":[]},"action":"accept","raw_text":"-A FORWARD -j ACCEPT"}
        rule=parse_rule(mutant)
        self.assertFalse(guarded(rule,"red","gray"))
        self.assertFalse(rule_policy_covered(rule,[check_installed_policy(self.tunnel)]))

    def test_missing_required_encryption_policy_fails(self):
        mutant=copy.deepcopy(self.tunnel)
        mutant["policies"]=""
        self.assertFalse(check_installed_policy(mutant)["passed"])

    def test_wrong_peer_fails(self):
        mutant=copy.deepcopy(self.tunnel)
        mutant["endpoints"]["remote"]="10.255.255.254"
        self.assertFalse(check_installed_policy(mutant)["passed"])

    def test_wrong_request_id_fails_coverage(self):
        rule=parse_rule(self.chain["ordered_rules"][0])
        for atom in rule["atoms"]:
            if atom["kind"] in {"inboundPolicy","outboundPolicy"}:
                atom["value"] += 999
        self.assertFalse(rule_policy_covered(rule,[check_installed_policy(self.tunnel)]))

    def test_broadened_selector_fails_coverage(self):
        rule=parse_rule(self.chain["ordered_rules"][0])
        for atom in rule["atoms"]:
            if atom["kind"]=="sourceRange":
                atom["low"],atom["high"]=0,4294967295
        self.assertFalse(rule_policy_covered(rule,[check_installed_policy(self.tunnel)]))

    def test_multiple_sa_records_cannot_mix_modes(self):
        mutant=copy.deepcopy(self.tunnel)
        mutant["observed_state"] += "\n" + self.tunnel["observed_state"].replace("AES_GCM_16-256","AES_CBC_256")
        with self.assertRaisesRegex(Unsupported,"ambiguous"):
            parse_observed_modes(mutant)

    def test_observed_sa_wrong_peer_rejected(self):
        mutant=copy.deepcopy(self.tunnel)
        mutant["endpoints"]["remote"]="10.255.255.254"
        with self.assertRaisesRegex(Unsupported,"endpoints"):
            parse_observed_modes(mutant)

    def test_unknown_module_rejected(self):
        mutant=copy.deepcopy(self.chain["ordered_rules"][0])
        mutant["matches"]["iptables_tokens"] += ["-m","unknown"]
        with self.assertRaises(Unsupported):
            parse_rule(mutant)

    def test_negation_is_not_silently_dropped(self):
        mutant={"ordinal":0,"matches":{"iptables_tokens":["!","-s","10.0.0.0/8"]},"action":"accept","raw_text":"synthetic negation"}
        with self.assertRaises(Unsupported):
            parse_rule(mutant)

if __name__=="__main__":
    unittest.main()
