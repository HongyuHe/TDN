"""Retain namespace-local records without assigning an architectural data zone."""
import copy
import json
import ipaddress
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "construction"))
from outer_gray_records import project


class SourceZoneProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = json.loads((ROOT / "data/evidence/continuation/OuterToGray_Baseline.json").read_text())["rawBundle"]

    def test_local_interfaces_are_retained_with_exact_zone(self):
        projected = project(self.bundle)
        interfaces = {row["id"]: row for row in projected["interfaces"]}
        raw = {row["interfaceId"]: row for row in self.bundle["ifaceBindings"]}
        self.assertEqual(set(interfaces), set(raw))
        local = [row for row in raw.values() if row["declaredZone"] == "local"]
        self.assertTrue(local)
        self.assertTrue(any(row["linkKind"] == "loopback" for row in local))
        self.assertTrue(any(not row["observedUp"] for row in local))
        for row in raw.values():
            self.assertEqual(interfaces[row["interfaceId"]]["zone"], row["declaredZone"])
            self.assertEqual(interfaces[row["interfaceId"]]["physical"], row["emulatedAttachment"])
        self.assertEqual(projected["nativeIfaces"], self.bundle["ports"])
        self.assertEqual(projected["nativeDevices"], self.bundle["devices"])
        self.assertEqual(projected["rawBundle"], self.bundle)

    def test_local_addresses_match_each_recorded_namespace(self):
        projected = project(self.bundle)
        native = {row["id"]: row for row in self.bundle["sourceInterfaces"]}
        owners = {row["id"]: row["device_id"] for row in self.bundle["sourceInterfaces"]}
        for interface in projected["interfaces"]:
            source = native[interface["id"]]
            expected = []
            for row in source["addresses"]:
                if row["family"] in ["inet", "inet6"]:
                    address = ipaddress.ip_address(row["local"])
                    expected.append(int(address) + (2 ** 128 if address.version == 6 else 0))
            self.assertEqual(interface["namespaceAddresses"], expected)
            self.assertEqual(interface["device"], owners[interface["id"]])
        loopback = int(ipaddress.ip_address("127.0.0.1"))
        namespaces = {row["device"] for row in projected["interfaces"]
                      if loopback in row["namespaceAddresses"]}
        self.assertGreater(len(namespaces), 1)
        for name, owner in self.bundle["deviceIds"].items():
            actual = {address for row in projected["interfaces"] if row["device"] == name
                      for address in row["namespaceAddresses"]}
            self.assertEqual(actual, set(self.bundle["devices"][owner]["localAddresses"]))

    def test_unknown_zone_is_rejected(self):
        changed = copy.deepcopy(self.bundle)
        changed["ifaceBindings"][0]["declaredZone"] = "unrecognized"
        with self.assertRaisesRegex(ValueError, "unknown declared interface zone"):
            project(changed)


if __name__ == "__main__":
    unittest.main()
