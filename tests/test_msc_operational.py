"""Check that operational evidence remains visible and unsupported semantics fail."""

import copy
import json
from pathlib import Path
import re
import unittest

from scripts import import_msc_snapshot as importer
from scripts import msc_operational as parser


class OperationalEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = importer.CURRENT_EVIDENCE / "snapshot"
        cls.status = json.loads((cls.snapshot / "status.json").read_text())
        cls.observations = {d["device"]: d for d in cls.status["devices"]}

    def test_host_xfrm_absence_is_observed_and_missing_capture_stays_unknown(self):
        for name in ["R_A1", "R_A2", "R_B1", "R_B2"]:
            original = copy.deepcopy(self.observations[name])
            data = parser.parse_operational(original, {"mgmt"})
            self.assertEqual(data["policies"], [])
            self.assertEqual(data["states"], [])
            for field, key in [("policies", "policies"), ("xfrm", "states")]:
                changed = copy.deepcopy(original)
                del changed["facts"][field]
                self.assertIsNone(parser.parse_operational(changed, {"mgmt"})[key])

    def test_removed_evidence_remains_distinct_from_empty_observations(self):
        original = copy.deepcopy(self.observations["O_A1"])
        original_data = parser.parse_operational(original, {"mgmt"})
        for field, name, empty in [("interfaces", "interfaces", "[]"), ("routes", "routes", "[]"),
                                   ("policies", "policies", ""), ("xfrm", "states", "")]:
            changed = copy.deepcopy(original)
            changed["facts"][field] = empty
            self.assertEqual(parser.parse_operational(changed, {"mgmt"})[name], [])
            self.assertNotEqual(original_data[name], [])
            del changed["facts"][field]
            self.assertIsNone(parser.parse_operational(changed, {"mgmt"})[name])

    def test_forwarding_mtu_peer_and_next_hop_changes_survive_translation(self):
        original = copy.deepcopy(self.observations["O_A1"])
        expected = parser.parse_operational(original, {"mgmt"})
        original["facts"]["forwarding"] = "0"
        ports = json.loads(original["facts"]["interfaces"])
        gray = next(p for p in ports if p["ifname"] == "gray")
        gray["mtu"] -= 1
        gray["link_index"] += 1
        original["facts"]["interfaces"] = json.dumps(ports)
        routes = json.loads(original["facts"]["routes"])
        next(r for r in routes if "gateway" in r)["gateway"] = "192.0.2.1"
        original["facts"]["routes"] = json.dumps(routes)
        actual = parser.parse_operational(original, {"mgmt"})
        for key in ["forwarding", "interfaces", "routes"]:
            self.assertNotEqual(actual[key], expected[key])

    def test_policy_selector_direction_and_request_id_survive_translation(self):
        text = self.observations["O_A1"]["facts"]["policies"]
        expected = parser.parse_policies(text)
        for before, after in [("dir out", "dir in"), ("reqid 201", "reqid 999"),
                              ("10.100.1.2/32", "10.100.1.0/24")]:
            self.assertIn(before, text)
            self.assertNotEqual(parser.parse_policies(text.replace(before, after)), expected)

    def test_unsupported_route_and_policy_semantics_are_rejected(self):
        route = json.loads(self.observations["O_A1"]["facts"]["routes"])[0]
        route["multipath"] = [{"gateway": "192.0.2.1"}]
        with self.assertRaisesRegex(ValueError, "unsupported routing"):
            parser.parse_routes(json.dumps([route]), set())
        route.pop("multipath")
        for action in ["throw", "blackhole", "unreachable", "prohibit"]:
            route["type"] = action
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "unsupported routing action"):
                parser.parse_routes(json.dumps([route]), set())
        with self.assertRaisesRegex(ValueError, "unsupported (socket )?XFRM policy"):
            parser.parse_policies(self.observations["O_A1"]["facts"]["policies"] + "mark 0x1\n")

    def test_added_switch_flow_is_preserved_as_non_normal(self):
        facts = copy.deepcopy(self.observations["G_A1"]["facts"])
        self.assertTrue(parser.parse_switch(facts, set())["normalOnly"])
        facts["openflow"] += "cookie=0, table=0, priority=10,ip actions=output:2\n"
        self.assertFalse(parser.parse_switch(facts, set())["normalOnly"])

    def test_route_scope_and_expanded_next_hop_identity_are_retained(self):
        raw = json.loads(self.observations["BLACK"]["facts"]["routes"])
        original = next(row for row in raw if "nhid" in row)
        parsed = parser.parse_routes(json.dumps([original]), set())[0]
        self.assertEqual(parsed["nextHopId"], original["nhid"])
        self.assertEqual(parsed["scope"], "global")
        self.assertEqual(parsed["gateway"], parser.ipv4(original["gateway"]))
        changed = {**original, "scope": "host", "nhid": original["nhid"] + 1}
        other = parser.parse_routes(json.dumps([changed]), set())[0]
        self.assertEqual(other["scope"], "host")
        self.assertNotEqual(other["nextHopId"], parsed["nextHopId"])
        for field in ["gateway", "dev"]:
            incomplete = dict(original)
            del incomplete[field]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "expanded|next-hop"):
                parser.parse_routes(json.dumps([incomplete]), set())

    def test_xfrm_template_spi_is_retained_and_zero_means_wildcard(self):
        text = self.observations["O_A1"]["facts"]["policies"]
        before = parser.parse_policies(text)
        self.assertGreater(next(p["spi"] for p in before if p["direction"] == "out"), 0)
        self.assertEqual(next(p["spi"] for p in before if p["direction"] == "in"), 0)
        changed = re.sub(r"spi 0x[0-9a-f]+", "spi 0x12345678", text)
        self.assertNotEqual(before, parser.parse_policies(changed))

    def test_xfrm_flags_encapsulation_address_and_unknown_fields(self):
        text = self.observations["O_A1"]["facts"]["xfrm"]
        states = parser.parse_states(text)
        self.assertTrue(all(state["flags"] == 32 for state in states))
        first = parser.blocks(text)[0]
        encap = parser.parse_states(first + "\n\tencap type espinudp sport 4500 dport 4500 addr 192.0.2.9\n")[0]
        self.assertEqual(encap["udpOriginalAddress"], parser.ipv4("192.0.2.9"))
        self.assertTrue(encap["udpEncapsulation"])
        for changed in [first.replace("af-unspec", "nopmtudisc"),
                        first + "\n\textra_flag oseq-may-wrap\n",
                        first + "\n\tunknown-state-setting 1\n",
                        first + "\n\taead cipher_null <<Keys hidden>> 128\n"]:
            with self.subTest(changed=changed[-60:]), self.assertRaisesRegex(ValueError, "unsupported"):
                parser.parse_states(changed)

    def test_address_lifetimes_and_dynamic_flag_remain_visible(self):
        rows = json.loads(self.observations['I_A1']['facts']['interfaces'])
        gray = next(row for row in rows if row['ifname'] == 'gray')
        baseline = parser.parse_interfaces(json.dumps([gray]), set())[0]
        self.assertFalse(baseline['addressMetadata'][0]['dynamic'])
        self.assertEqual(baseline['addressMetadata'][0]['validLifetime'], 4294967295)
        gray['addr_info'][0].update(dynamic=True, valid_life_time=3600)
        changed = parser.parse_interfaces(json.dumps([gray]), set())[0]
        self.assertTrue(changed['addressMetadata'][0]['dynamic'])
        self.assertEqual(changed['addressMetadata'][0]['validLifetime'], 3600)
        del gray['addr_info'][0]['valid_life_time']
        missing = parser.parse_interfaces(json.dumps([gray]), set())[0]
        self.assertIsNone(missing['addressMetadata'])

    def test_local_rule_widening_changes_imported_chain(self):
        text = (self.snapshot / "devices/O_A1/observed.iptables").read_text()
        before = importer.parse_forward_data(text, "O_A1", "OUTPUT", {"mgmt"})
        after = importer.parse_forward_data(text.replace("COMMIT", "-A OUTPUT -p tcp -j ACCEPT\nCOMMIT"),
                                            "O_A1", "OUTPUT", {"mgmt"})
        self.assertEqual(len(after["rules"]), len(before["rules"]) + 1)
        self.assertNotEqual(before, after)

    def test_optional_management_rules_do_not_enter_required_chains(self):
        text = (self.snapshot / "devices/O_A1/observed.iptables").read_text()
        changed = text.replace("COMMIT", "-A OUTPUT -o mgmt -m unsupported --unknown value -j ACCEPT\nCOMMIT")
        for chain in ["INPUT", "OUTPUT"]:
            self.assertEqual(importer.parse_forward_data(text, "O_A1", chain, {"mgmt"}),
                             importer.parse_forward_data(changed, "O_A1", chain, {"mgmt"}))
        with self.assertRaisesRegex(ValueError, "unsupported"):
            importer.parse_forward_data(changed.replace("-o mgmt", "-o black"), "O_A1", "OUTPUT", {"mgmt"})


if __name__ == "__main__":
    unittest.main()
