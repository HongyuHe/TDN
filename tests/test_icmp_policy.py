"""Check exact ICMP type, code and hop-limit translation without live traffic."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "construction"))
from import_snapshot import parse_rule, Unsupported
from generate_execution_witness import atom_holds


def parse(tokens):
    return parse_rule({"matches": {"iptables_tokens": tokens}, "action": "accept",
                       "ordinal": 0, "raw_text": "fixture"})


class ICMPPolicyTests(unittest.TestCase):
    def test_type_and_code_are_separate(self):
        atoms = parse(["-p", "icmp", "-m", "icmp", "--icmp-type", "3/4"])["atoms"]
        self.assertIn({"kind": "icmpType", "value": 3}, atoms)
        self.assertIn({"kind": "icmpCode", "value": 4}, atoms)
        self.assertFalse(all(atom_holds(a, {"protocol": "icmp", "icmpType": 3, "icmpCode": 0}) for a in atoms))

    def test_neighbor_discovery_requires_type_and_hop_limit(self):
        atoms = parse(["-p", "ipv6-icmp", "-m", "icmp6", "--icmpv6-type", "135",
                       "-m", "hl", "--hl-eq", "255"])["atoms"]
        good = {"protocol": "ipv6-icmp", "icmpType": 135, "hopLimit": 255}
        self.assertTrue(all(atom_holds(a, good) for a in atoms))
        for changed in [{"icmpType": 128}, {"icmpType": 1}, {"hopLimit": 64}]:
            self.assertFalse(all(atom_holds(a, {**good, **changed}) for a in atoms))

    def test_wrong_protocol_rejected(self):
        for tokens in [["-p", "tcp", "--icmp-type", "8"],
                       ["-p", "icmp", "--icmpv6-type", "128"],
                       ["--icmp-type", "8"]]:
            with self.assertRaises(Unsupported):
                parse(tokens)

    def test_bounds_and_unimplemented_syntax_rejected(self):
        for value in ["256", "3/256", "-1", "echo-request", "3:5", "3/4/5"]:
            with self.assertRaises(Unsupported):
                parse(["-p", "icmp", "--icmp-type", value])

    def test_type_without_code_does_not_constrain_code(self):
        atoms = parse(["-p", "icmp", "--icmp-type", "3"])["atoms"]
        self.assertTrue(all(atom_holds(a, {"protocol": "icmp", "icmpType": 3, "icmpCode": 4}) for a in atoms))
        self.assertFalse(any(a["kind"] == "icmpCode" for a in atoms))

    def test_hop_limit_requires_module(self):
        with self.assertRaises(Unsupported):
            parse(["--hl-eq", "255"])


if __name__ == "__main__":
    unittest.main()
