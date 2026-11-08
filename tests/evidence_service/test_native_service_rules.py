"""Check captured native service rules and reject altered boundary conditions."""
import copy
import json
from pathlib import Path
import unittest

from tdn_evidence.parsers.native_nft import check_ruleset


class NativeServiceRulesTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((Path(__file__).parent / "fixtures/native-red-service-nft.json").read_text())

    def check(self):
        return check_ruleset(self.fixture["nft"], self.fixture["chains"])

    def port_match(self):
        return next(expr["match"] for item in self.fixture["nft"]["nftables"]
                    if "rule" in item for expr in item["rule"]["expr"]
                    if expr.get("match", {}).get("left", {}).get("payload", {}).get("protocol") == "tcp")

    def test_captured_service_rules_match(self):
        result = self.check()
        self.assertGreater(result["rules"], 8)

    def test_altered_transport_values_are_rejected(self):
        original = copy.deepcopy(self.fixture)
        for value in [8081, -1, 65536, True, "8080", {"range": [8080, 8081]}]:
            with self.subTest(value=value):
                self.fixture = copy.deepcopy(original)
                self.port_match()["right"] = value
                with self.assertRaises(ValueError):
                    self.check()

    def test_altered_transport_protocol_and_field_are_rejected(self):
        original = copy.deepcopy(self.fixture)
        for key, value in [("protocol", "udp"), ("protocol", "th"), ("field", "flags"), ("field", "sport")]:
            with self.subTest(key=key, value=value):
                self.fixture = copy.deepcopy(original)
                self.port_match()["left"]["payload"][key] = value
                with self.assertRaises(ValueError):
                    self.check()

    def test_missing_icmp_matcher_is_rejected(self):
        rule = next(item["rule"] for item in self.fixture["nft"]["nftables"]
                    if "rule" in item and any(expr.get("xt", {}).get("name") == "icmp"
                                              for expr in item["rule"]["expr"]))
        rule["expr"] = [expr for expr in rule["expr"] if expr.get("xt", {}).get("name") != "icmp"]
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_port_and_reordered_rules_are_rejected(self):
        original = copy.deepcopy(self.fixture)
        del self.port_match()["right"]
        with self.assertRaises(ValueError):
            self.check()
        self.fixture = original
        rules = [item["rule"] for item in self.fixture["nft"]["nftables"]
                 if "rule" in item and item["rule"]["chain"] == "FORWARD"]
        rules[1]["expr"], rules[2]["expr"] = rules[2]["expr"], rules[1]["expr"]
        with self.assertRaises(ValueError):
            self.check()


if __name__ == "__main__":
    unittest.main()
