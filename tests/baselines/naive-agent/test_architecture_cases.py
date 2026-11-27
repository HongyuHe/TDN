import json
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from architecture_cases import (
    ANY,
    FAMILIES,
    SPI,
    esp_rules,
    observed_links,
)
from cohort import NETWORKS, runtime_profile, require_current_run
from observed_profile import capture_topology
from run_architecture_trial import check_packets, verify_change, verify_restored
from score_trials import KNOWN_TYPES


class ArchitectureCases(unittest.TestCase):
    def test_replicas_preserve_every_reference_and_never_name_original_devices(self):
        for n in NETWORKS:
            root = Path(__file__).parent / "profiles" / "native"
            original = json.loads((root / (n + ".json")).read_text())["topology"]
            copy = runtime_profile(n)["topology"]
            names = dict(
                zip(
                    (d["id"] for d in copy["devices"]),
                    (d["id"] for d in original["devices"]),
                )
            )
            self.assertTrue(names.keys().isdisjoint(names.values()))

            def reverse(v):
                if isinstance(v, list):
                    return [reverse(x) for x in v]
                if isinstance(v, dict):
                    return {k: reverse(x) for k, x in v.items()}
                return names.get(v, v) if isinstance(v, str) else v

            restored = reverse(copy)
            restored["name"] = original["name"]
            self.assertEqual(restored, original)
        with self.assertRaises(ValueError):
            runtime_profile("net-02")

    def test_retained_header_and_forwarding_cases_target_only_copy_devices(self):
        from delivery_lab import selection

        for name in NETWORKS:
            p = runtime_profile(name)
            devices = {d["id"] for d in p["topology"]["devices"]}
            for family in (
                "inner-empty-ipv4-header",
                "firewall-local-empty-udp",
                "outer-eligible-deny",
            ):
                case = selection(p, family)
                self.assertIn(case["device"], devices)
                self.assertIn(case.get("source_device", case["device"]), devices)
            for old in ("delivery-outage", "gray-eligible-deny"):
                with self.assertRaises(ValueError):
                    selection(p, old)

    def test_retired_run_cannot_become_current(self):
        with TemporaryDirectory() as t:
            p = Path(t)
            (p / "protocol.json").write_text(
                json.dumps({"original_profiles": ["net-02", *NETWORKS]})
            )
            with self.assertRaises(ValueError):
                require_current_run(p)
        self.assertEqual(
            {KNOWN_TYPES[k]["clause_ids"][0] for k in FAMILIES},
            {"RG-008.01", "RG-013.01", "RG-040.02"},
        )
        self.assertFalse(
            set(KNOWN_TYPES)
            & {"delivery-outage", "gray-firewall-detached", "gray-eligible-deny"}
        )

    def test_undeclared_link_requires_a_reciprocal_observation(self):
        topo = {
            "devices": [
                {"id": name, "role": "inner", "interfaces": []} for name in ("a", "b")
            ],
            "links": [],
        }

        def port(i, peer):
            return {
                "ifname": "lan2",
                "ifindex": i,
                "link_index": peer,
                "flags": ["UP", "LOWER_UP"],
                "mtu": 1500,
                "addr_info": [],
                "linkinfo": {"info_kind": "veth"},
            }

        readings = {"a": [port(21, 22)], "b": [port(22, 21)]}
        expanded = capture_topology(topo, readings)
        self.assertEqual(topo["links"], [])
        self.assertEqual(len(expanded["links"]), 1)
        ds = {d["id"]: d for d in expanded["devices"]}
        _, zones, links = observed_links(
            ds, {(n, "interfaces"): json.dumps(v) for n, v in readings.items()}
        )
        self.assertEqual(links, [(("a", "lan2"), ("b", "lan2"))])
        self.assertEqual(set(zones.values()), {"unknown"})
        assigned = capture_topology(topo, readings, {("a", "lan2"): "gray"})
        self.assertEqual([d["interfaces"][0]["zone"] for d in assigned["devices"]], ["gray", "gray"])
        readings["b"][0]["link_index"] = 99
        with self.assertRaises(ValueError):
            capture_topology(topo, readings)

    def test_forwarding_preserves_rule_order_and_spi(self):
        text = """*filter
:FORWARD DROP [0:0]
-A FORWARD -p esp -m esp --espspi 1413762609 -j DROP
-A FORWARD -s 10.100.1.2/32 -p esp -j ACCEPT
-A FORWARD -p udp -m udp --dport 500 -j ACCEPT
COMMIT"""
        rules, default = esp_rules(text)
        self.assertFalse(default)
        self.assertEqual([r["permit"] for r in rules], [False, True])
        self.assertEqual(rules[0]["spi"], (1413762609, 1413762609))
        self.assertEqual(rules[1]["spi"], ANY)
        with self.assertRaises(ValueError):
            esp_rules(text.replace("--espspi", "--unknown"))

    def test_two_firewall_captures_must_match(self):
        p = {
            "source": int.from_bytes(bytes([10, 100, 1, 2]), "big"),
            "destination": int.from_bytes(bytes([10, 100, 2, 2]), "big"),
            "ingress": "s1",
            "egress": "s2",
        }
        incoming = {
            "iface": "s1",
            "source": "10.100.1.2",
            "destination": "10.100.2.2",
            "spi": SPI,
            "seq": 1,
            "protocol": 50,
            "esp_sha256": "af" * 32,
        }
        outgoing = {**incoming, "iface": "s2"}
        record = {
            "evidence": {"packet": p},
            "packet_observations": {"ingress": [incoming], "egress": [outgoing]},
        }
        check_packets(record, True)
        for key, value in (
            ("seq", 2),
            ("iface", "s1"),
            ("destination", "10.100.2.3"),
            ("esp_sha256", "ad" * 32),
        ):
            changed = deepcopy(record)
            changed["packet_observations"]["egress"][0][key] = value
            with self.assertRaises(ValueError):
                check_packets(changed, True)
        record["packet_observations"]["egress"] = []
        check_packets(record, False)
        with self.assertRaises(ValueError):
            check_packets(record, True)

    def test_lost_path_and_shared_label_cannot_establish_a_replacement(self):
        before = {
            "evidence": {
                "levels": ["A", "B"],
                "endpoints": [0, 1],
                "edges": [],
                "reds": [],
                "espRules": [],
                "regions": [0, 1],
                "packet": {},
            },
            "witness": {
                "gateways": ["a", "b"],
                "firewall": "f",
                "gray_path": None,
                "assignments": {"X": ["a"], "Y": ["b"]},
            },
        }
        for family in FAMILIES:
            with self.assertRaises(ValueError):
                verify_change(family, before, deepcopy(before))
        after = deepcopy(before)
        after["evidence"]["regions"] = [0, 0]
        with self.assertRaises(ValueError):
            verify_restored("gray-cross-level-path", before, after)


class LeanFirewallPolicyTests(unittest.TestCase):
    def test_other_firewall_and_single_spi_respect_rule_order(self):
        from architecture_cases import ANY
        from measure import typecheck

        source = Path(__file__).with_name("MscArchitectureChecks.lean")
        levels = [
            {
                "id": n,
                "site": "Z",
                "level": {
                    "classification": n,
                    "compartments": [],
                    "dissemination": [],
                    "otherControls": [],
                },
                "innerComponents": [n],
            }
            for n in ("one", "two")
        ]
        rule = {
            "source": [19, 19],
            "destination": [41, 41],
            "ingress": "east",
            "egress": "west",
            "spi": [197001, 197001],
            "permit": True,
        }
        policy = {"ifaces": ["east", "west"], "rules": [rule], "defaultAllow": False}
        inputs = {
            "reds": levels,
            "nodeCount": 4,
            "edges": [],
            "inners": [0, 1],
            "firewalls": [2, 3],
            "levels": ["one", "two", "", ""],
            "regions": [0, 1, 2, 3],
            "grayAcls": [
                {"ifaces": ["a", "b"], "rules": [], "defaultAllow": False},
                policy,
            ],
            "innerAddresses": [
                {"address": 19, "level": "one"},
                {"address": 41, "level": "two"},
            ],
        }
        with TemporaryDirectory() as temp:

            def check(tag):
                return typecheck(source, Path(temp) / tag, inputs, {"  native_decide"})

            rejected = check("permit")
            self.assertEqual(rejected["status"], "rejected")
            self.assertEqual(
                [s.split()[1] for s in rejected["failed_obligations"]],
                ["protected_gray_forwarding_respects_levels"],
            )
            policy["rules"].insert(0, {**rule, "spi": ANY, "permit": False})
            self.assertEqual(check("first-deny")["status"], "pass")
