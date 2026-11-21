"""Check which observations an adapter may supply for each proof input."""
import copy
import unittest
from tdn_evidence.contracts import FAMILIES, check_saved, describe, installed_route_observations
from tdn_evidence.adapters import ADAPTERS, Adapter, Capability, linux_routes

class EvidenceRequirementsTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {"consistency": "stable-during-recheck", "devices": [{"id": "r1"}], "observations": [
            {"id": f"r1.fib{n}", "device": "r1", "adapter": "linux", "parser_version": ADAPTERS["linux"].version,
             "capability": f"fib{n}", "status": "observed", "sha256": "fixture", "records": []} for n in (4, 6)]}
        self.manifest["observations"] += [
            {"id": f"r1.fib{n}.recheck", "device": "r1", "adapter": "recheck", "capability": f"r1.fib{n}",
             "status": "observed", "sha256": "fixture", "records": [{"unchanged": True}]} for n in (4, 6)]

    def test_successful_empty_families_are_observations(self):
        self.assertEqual(installed_route_observations(self.manifest), {"r1.fib4": 4, "r1.fib6": 6})

    def test_bird_and_frr_candidates_do_not_replace_forwarding_observations(self):
        for vendor in ("bird", "frr"):
            with self.subTest(vendor=vendor):
                m = copy.deepcopy(self.manifest)
                m["observations"][0].update(adapter=vendor, capability="routes", parser_version=ADAPTERS[vendor].version)
                with self.assertRaisesRegex(ValueError, "r1: fib4"):
                    installed_route_observations(m)

    def test_adapter_with_its_own_capability_names(self):
        self.addCleanup(ADAPTERS.pop, "installed-fib-test")
        ADAPTERS["installed-fib-test"] = Adapter("adapter-1", {
            f"forward{n}": Capability((), linux_routes, "Installed routes", True, tag)
            for tag, n in FAMILIES.items()})
        for o, n in zip(self.manifest["observations"][:2], (4, 6), strict=True):
            o.update(adapter="installed-fib-test", capability=f"forward{n}", parser_version="adapter-1")
        self.assertIn("installed-fib-test.forward6", describe("live", "inventory")["providers"]["installed-ipv6-routes"])
        self.assertEqual(len(installed_route_observations(self.manifest)), 2)

    def test_recorded_contract_survives_adapter_removal(self):
        for o, tag in zip(self.manifest["observations"][:2], FAMILIES, strict=True):
            o.update(adapter="retired", provides=tag)
        self.assertEqual(len(installed_route_observations(self.manifest)), 2)

    def test_missing_field_reports_device_family_and_field(self):
        row = linux_routes('[{"dst":"default","dev":"eth0"}]')[0]
        del row["metric"]
        self.manifest["observations"][0]["records"] = [row]
        with self.assertRaisesRegex(ValueError, r"r1.IPv4.*missing field metric"):
            installed_route_observations(self.manifest)

    def test_invalid_route_value_names_the_field(self):
        row = linux_routes('[{"dst":"default","dev":"eth0"}]')[0]
        row["table"] = -1
        self.manifest["observations"][0]["records"] = [row]
        with self.assertRaisesRegex(ValueError, r"r1.IPv4.*table: expected natural number"):
            installed_route_observations(self.manifest)

    def test_unrelated_stable_observation_is_insufficient(self):
        self.manifest["observations"].pop()
        with self.assertRaisesRegex(ValueError, "r1.fib6: missing unchanged recheck"):
            installed_route_observations(self.manifest)

    def test_duplicate_sources_are_ambiguous(self):
        self.manifest["observations"].append(self.manifest["observations"][0])
        with self.assertRaisesRegex(ValueError, "duplicate IPv4"):
            installed_route_observations(self.manifest)

    def test_saved_contract_requires_only_its_inputs(self):
        snapshot = {"devices": [], "links": [], "interfaces": []}
        check_saved("topology", snapshot)
        with self.assertRaisesRegex(ValueError, "missing observation table filters"):
            check_saved("multi_protocol_execution", snapshot)
        snapshot.update(filters=[], routes=[], tunnels=[], observations=[],
                        devices=[{"id": "r1", "role": "outer", "namespace": "r1"}])
        with self.assertRaisesRegex(ValueError, "missing successful interfaces observation on r1"):
            check_saved("multi_protocol_execution", snapshot)
        self.assertIn("policies", describe("saved", "multi_protocol_execution")["required_per_device"])
