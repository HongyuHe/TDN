"""Check that boundary projection retains native interfaces, programs and provenance."""
import copy
import ipaddress
import json
from pathlib import Path
import unittest

from outer_gray_records import project


class ProjectionTests(unittest.TestCase):
    def captures(self):
        for name in ("Baseline", "Shared"):
            path = Path("data/evidence/continuation") / ("OuterGray" + name + ".json")
            saved = json.loads(path.read_text())
            yield name, saved["rawBundle"], saved["records"]

    def test_projection_is_reproducible_and_raw_bundle_is_exact(self):
        for name, bundle, records in self.captures():
            result = project(bundle)
            self.assertEqual(result["rawBundle"], bundle, name)
            self.assertEqual({key: result[key] for key in records}, records, name)

    def test_all_ports_interfaces_and_loopbacks_are_retained(self):
        for name, bundle, records in self.captures():
            self.assertEqual(records["nativeIfaces"], bundle["ports"], name)
            self.assertEqual(records["ifaceNames"], [item["id"] for item in records["interfaces"]], name)
            self.assertEqual(set(records["ifaceNames"]), {item["id"] for item in bundle["sourceInterfaces"]}, name)
            self.assertEqual(len(records["ifaceNames"]), len(bundle["ports"]), name)
            loopbacks = [item for item in bundle["sourceInterfaces"] if item["name"] == "lo"]
            self.assertGreater(len(loopbacks), 1, name)
            for interface in loopbacks:
                self.assertIn(interface["id"], records["ifaceNames"])
                self.assertTrue(any(address["local"] == "127.0.0.1" for address in interface["addresses"]))

    def test_every_declared_gray_interface_keeps_its_address_and_four_programs(self):
        for name, bundle, records in self.captures():
            raw = {item["id"]: item for item in bundle["sourceInterfaces"]}
            projected = {item["id"]: item for item in records["interfaces"]}
            gray = [item for item in bundle["ifaceBindings"] if item["declaredZone"] == "gray"]
            self.assertGreater(len(gray), 0, name)
            for binding in gray:
                interface = projected[binding["interfaceId"]]
                addresses = [int(ipaddress.ip_address(item["local"])) for item in raw[interface["id"]]["addresses"] if item["family"] == "inet"]
                self.assertEqual(addresses, [interface["address"]] if interface["address"] is not None else [], name)
                if any(item["id"] == interface["device"] and item["role"] == "outer" for item in bundle["sourceDevices"]):
                    self.assertEqual(len(addresses), 1, name)
                self.assertEqual(interface["zone"], "gray", name)
                policies = [item for item in records["policies"] if item["interface"] == interface["id"]]
                self.assertEqual(len(policies), 4 if addresses else 0, name)
                device = bundle["devices"][binding["ownerId"]]
                for policy in policies:
                    self.assertEqual(policy["rules"], device[policy["hook"] + "Rules"], name)
                    self.assertEqual(policy["defaultVerdict"], device[policy["hook"] + "Fallback"], name)

    def test_native_programs_routes_and_attachments_are_unchanged(self):
        for name, bundle, records in self.captures():
            for target, source in (("nativeDevices", "devices"), ("routes", "routes"), ("links", "links"), ("bridges", "bridges")):
                self.assertEqual(records[target], bundle[source], name)

    def test_wrong_native_owner_is_rejected(self):
        for _, bundle, _ in self.captures():
            tampered = copy.deepcopy(bundle)
            tampered["ports"][0]["owner"] = (tampered["ports"][0]["owner"] + 1) % len(tampered["devices"])
            with self.assertRaisesRegex(ValueError, "ownership mismatch"):
                project(tampered)

    def test_wrong_native_hook_name_is_rejected(self):
        for _, bundle, _ in self.captures():
            tampered = copy.deepcopy(bundle)
            tampered["ports"][0]["name"] = "different-hook"
            with self.assertRaisesRegex(ValueError, "hook name mismatch"):
                project(tampered)


if __name__ == "__main__":
    unittest.main()
