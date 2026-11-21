"""Keep earlier typed records readable and retain the original device observations."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/construction"))
from migrate_typed_overlay_records import upgrade_typed_records


class TypedOverlayRecordTests(unittest.TestCase):
    def test_raw_and_typed_records_in_one_export(self):
        tunnel = {"id": "inner", "sender": "A", "receiver": "B", "layer": "inner",
                  "keyContext": "inner-key", "espTunnelMode": True,
                  "associatedIPTunnel": False, "mechanism": "ipsec"}
        iface = {"id": "A:lo", "device": "A", "zone": "local", "address": None,
                 "namespaceAddresses": [], "physical": False, "externalData": False}
        raw = {"tunnels": [{"id": "inner", "device_id": "A", "mechanism": "IPsec"}],
               "interfaces": [{"id": "A:lo", "device_id": "A", "zone": "local"}]}
        old = {"rawBundle": raw, "rawInventory": {"interfaces": [iface]}, "tunnels": [tunnel], "interfaces": [iface]}
        updated = upgrade_typed_records(old)
        self.assertEqual(updated["rawBundle"], raw)
        self.assertEqual(updated["rawInventory"], old["rawInventory"])
        self.assertEqual(updated["interfaces"][0]["zone"], "hostLocal")
        self.assertEqual(updated["tunnels"][0]["protocol"], "ipsec")
        self.assertNotIn("mechanism", updated["tunnels"][0])
        self.assertEqual(old["interfaces"][0]["zone"], "local")
        self.assertEqual(upgrade_typed_records(updated), updated)

    def test_ambiguous_typed_record_is_rejected(self):
        row = {"id": "s1", "device": "A", "peer": "B", "layer": "outer", "mode": "tunnel",
               "status": "observed", "observationIds": [], "protocol": "ipsec", "mechanism": "macsec"}
        with self.assertRaisesRegex(ValueError, "both the old field"):
            upgrade_typed_records(row)

    def test_overlay_and_pair_keep_the_protocols_in_order(self):
        old = {"zone": "local", "location": 1, "level": {}, "tunnelStack": [
            {"layer": "outer", "source": 2, "destination": 3, "mechanism": "macsec"},
            {"layer": "inner", "source": 1, "destination": 4, "mechanism": "ipsec"}]}
        converted = upgrade_typed_records(old)
        self.assertEqual(converted["zone"], "hostLocal")
        self.assertEqual([header["protocol"] for header in converted["tunnelStack"]], ["macsec", "ipsec"])
        pair = {"innerComponent": "A", "outerComponent": "B", "innerKeyContext": "i", "outerKeyContext": "o",
                "communicatingSites": ["east", "west"], "innerMechanism": "ipsec", "outerMechanism": "macsec"}
        converted = upgrade_typed_records(pair)
        self.assertEqual((converted["innerProtocol"], converted["outerProtocol"]), ("ipsec", "macsec"))

    def test_lookup_indexes_preserve_their_entries(self):
        self.assertEqual(upgrade_typed_records({"routes": [], "source_sha256": "hash", "certificates": [1]}),
                         {"routes": [], "source_sha256": "hash", "hints": [1]})
        table = {"index": {"earlierRules": [], "allowed": []}, "witnesses": [0]}
        self.assertEqual(upgrade_typed_records(table), {"index": table["index"], "permitHints": [0]})
        self.assertEqual(upgrade_typed_records({"certificates": ["X.509"]}), {"certificates": ["X.509"]})


if __name__ == "__main__":
    unittest.main()
