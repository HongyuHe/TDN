"""Validate aligned SA, bridge, source and full-frame sizing normalization."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/construction"))
import packet_sizing_records as records
import packet_sizing_cases as cases
import packet_sizing_continuation as continuation


class PacketSizingRecordsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = {name: json.loads((ROOT / f"data/evidence/continuation/MtuSizing_{name}.json").read_text())
                     for name in ["Baseline", "Shared"]}

    def test_both_complete_raw_state_pools_and_directions_reproduce(self):
        for saved in self.saved.values():
            actual = records.key_records(saved["rawNative"], saved["rawKeysBefore"], saved["rawKeysAfter"], saved["epoch"])
            self.assertEqual(actual, saved["publicInstallations"])
            self.assertEqual(len(actual), sum(len(device["states"]) for device in saved["rawNative"]["devices"]))
            self.assertEqual({row["installation"]["direction"] for row in actual}, {"inbound", "outbound"})

    def test_changed_epoch_key_material_is_rejected(self):
        saved = self.saved["Baseline"]
        after = copy.deepcopy(saved["rawKeysAfter"])
        after["associations"][0]["materials"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "material reference changed"):
            records.key_records(saved["rawNative"], saved["rawKeysBefore"], after, saved["epoch"])

    def test_wrong_policy_direction_is_rejected(self):
        saved = self.saved["Baseline"]
        native = copy.deepcopy(saved["rawNative"])
        owner = saved["installations"][0]["installation"]["device"]
        direction = saved["installations"][0]["installation"]["direction"]
        native["devices"][owner]["ingressPolicies" if direction == "inbound" else "egressPolicies"] = []
        with self.assertRaisesRegex(ValueError, "endpoint/policy binding"):
            records.key_records(native, saved["rawKeysBefore"], saved["rawKeysAfter"], saved["epoch"])

    def test_bridge_and_all_Red_attachments_reproduce(self):
        for saved in self.saved.values():
            endpoints, policies = records.bridge_records(saved["rawNative"], saved["rawBridge"])
            self.assertEqual(endpoints, saved["bridgeEndpoints"])
            self.assertEqual(policies, saved["linkPolicies"])
            self.assertEqual(records.source_records(saved["rawNative"]),
                             (saved["networks"], saved["sourceEntries"], saved["redNetworkAttachments"]))
            self.assertTrue(endpoints)
            self.assertTrue(saved["sourceEntries"])

    def test_bridge_omission_and_unmodeled_VLAN_are_rejected(self):
        saved = self.saved["Shared"]
        missing = copy.deepcopy(saved["rawBridge"])
        missing["switches"][0]["possibleSwitching"].pop()
        with self.assertRaisesRegex(ValueError, "bridging coverage"):
            records.bridge_records(saved["rawNative"], missing)
        changed = copy.deepcopy(saved["rawBridge"])
        changed["switches"][0]["ovsTables"]["port"][0]["tag"] = 100
        with self.assertRaisesRegex(ValueError, "VLAN/bond"):
            records.bridge_records(saved["rawNative"], changed)

    def test_all_frames_and_selected_paths_reproduce(self):
        with tempfile.TemporaryDirectory() as temporary:
            for name, saved in self.saved.items():
                source = Path(temporary) / f"Sizing{name}.json"
                target = Path(temporary) / "cases.json"
                source.write_text(json.dumps(saved))
                result = cases.build(source, target)
                expected = json.loads((ROOT / f"data/evidence/continuation/Sizing{name}Cases.json").read_text())
                for field in ["path", "frames", "cases"]:
                    self.assertEqual(result[field], expected[field])
                self.assertEqual(len(result["frames"]), len(saved["rawSizing"]["packets"]))

    def test_recorded_continuations_reproduce_mandatory_Outer_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            for name in self.saved:
                source = ROOT / f"data/evidence/continuation/MtuSizing_{name}.json"
                sample = ROOT / f"data/evidence/continuation/Sizing{name}Cases.json"
                target = Path(temporary) / "continuation.json"
                result = continuation.build(source, sample, target)
                expected = json.loads((ROOT / f"data/evidence/continuation/Sizing{name}Continuation.json").read_text())
                self.assertEqual(result, expected)
                self.assertTrue(result['endpoint'].endswith('O_A1:black'))
                self.assertEqual(result['transmission']['operation'], 'linkTransmit')
                self.assertEqual(sum(move['operation'] == 'encryptIPsec' for move in result['moves']), 1)

    def test_continuation_rejects_missing_Outbound_state_and_wrong_final_role(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "changed.json"
            target = Path(temporary) / "continuation.json"
            sample = ROOT / "data/evidence/continuation/SizingBaselineCases.json"
            saved = copy.deepcopy(self.saved['Baseline'])
            saved['installations'] = [row for row in saved['installations']
                                      if row['installation']['association']['reqid'] != 201]
            source.write_text(json.dumps(saved))
            with self.assertRaisesRegex(ValueError, 'one bound outbound state'):
                continuation.build(source, sample, target)
            saved = copy.deepcopy(self.saved['Baseline'])
            next(role for role in saved['sizingRoles'] if role['interface'].endswith('O_A1:black'))['role'] = 'other'
            source.write_text(json.dumps(saved))
            with self.assertRaisesRegex(ValueError, 'mandatory sizing interface'):
                continuation.build(source, sample, target)

    def test_unmatched_ESP_SPI_and_changed_frame_are_rejected(self):
        saved = copy.deepcopy(self.saved["Baseline"])
        packet = next(row for row in saved["rawSizing"]["packets"] if row["protocol"] == 50)
        frame = bytearray.fromhex(packet["frame_hex"])
        frame[34:38] = bytes.fromhex("01020304")
        packet["frame_hex"] = frame.hex()
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "changed.json"
            target = Path(temporary) / "cases.json"
            source.write_text(json.dumps(saved))
            with self.assertRaisesRegex(ValueError, "aligned sender/receiver"):
                cases.build(source, target)
            packet["frame_bytes"] += 1
            source.write_text(json.dumps(saved))
            with self.assertRaisesRegex(ValueError, "inconsistent captured"):
                cases.build(source, target)


if __name__ == "__main__":
    unittest.main()
