import copy
import json
from pathlib import Path
import unittest

from tdn_evidence.macsec_boundary import associations, decoded_frame, link_programs
from tdn_evidence.parsers.snapshot import EvidenceError


class MACsecBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((Path(__file__).parent / "fixtures/macsec-boundary-samples.json").read_text())

    def test_physical_allow_and_drop_are_preserved(self):
        before, after = self.fixture["policies"]
        allowed = link_programs(before["json"], before["text"])[1]
        denied = link_programs(after["json"], after["text"])[1]
        self.assertEqual(allowed["program"]["rules"][1]["verdict"], "allow")
        self.assertEqual(denied["program"]["rules"][1]["verdict"], "deny")
        self.assertEqual(denied["counters"]["plaintext"]["packets"], 3)

    def test_actual_physical_device_is_required(self):
        case = self.fixture["policies"][0]
        with self.assertRaisesRegex(EvidenceError, "binding missing"):
            link_programs(case["json"], case["text"].replace('device "wire"', 'device "other"'))

    def test_additional_rule_condition_is_rejected(self):
        case = copy.deepcopy(self.fixture["policies"][0])
        rule = next(row["rule"] for row in case["json"]["nftables"] if row.get("rule", {}).get("comment") == "plaintext")
        rule["expr"].insert(0, {"match": {"left": {"meta": {"key": "mark"}}, "op": "==", "right": 42}})
        with self.assertRaisesRegex(EvidenceError, "Unsupported physical match"):
            link_programs(case["json"], case["text"])

    def test_physical_frames_distinguish_protected_and_plain(self):
        protected, plain = map(decoded_frame, self.fixture["frames"])
        self.assertEqual(protected["header"]["etherType"], 0x88E5)
        self.assertEqual(protected["macsec"]["an"], 0)
        self.assertEqual(plain["header"]["etherType"], 0x0800)
        self.assertEqual(bytes.fromhex(plain["ipv4"]["payloadHex"]), b"TDN-MACSEC-PHYSICAL-BOUNDARY")
        self.assertEqual(plain["ipv4"]["ttl"], 63)

    def test_frame_hash_and_auxiliary_lengths_are_checked(self):
        altered = copy.deepcopy(self.fixture["frames"][1])
        altered["sha256"] = "0" * 64
        with self.assertRaisesRegex(EvidenceError, "hash differs"):
            decoded_frame(altered)
        altered = copy.deepcopy(self.fixture["frames"][1])
        altered["packetAuxiliary"]["snapLength"] -= 1
        with self.assertRaisesRegex(EvidenceError, "length differs"):
            decoded_frame(altered)

    def test_public_association_identity_is_retained(self):
        records = associations(self.fixture["associations"])
        self.assertEqual([record["direction"] for record in records], ["tx", "rx"])
        self.assertTrue(all(record["active"] for record in records))
        self.assertEqual(records[0]["publicKeyIdentifier"], "01" + "00" * 15)

    def test_integrity_only_keeps_macsec_framing_without_hiding_payload(self):
        row = self.fixture["integrityFrame"]
        frame = decoded_frame(row)
        self.assertEqual(frame["header"]["etherType"], 0x88E5)
        self.assertEqual(frame["macsec"]["tciAN"] & 0x0C, 0)
        self.assertIn(b"TDN-MACSEC-PHYSICAL-BOUNDARY", bytes.fromhex(row["bytes"]))


if __name__ == "__main__":
    unittest.main()
