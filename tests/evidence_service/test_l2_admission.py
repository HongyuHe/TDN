"""Reject changes that break the captured L2 filtering and framing guarantees."""

import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tdn_evidence.l2_admission import frame_record, parse, read_experiment_raw


class LinkAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        with tarfile.open(Path(__file__).parent / "fixtures/l2-admission-vlan-public.tar.gz") as archive:
            archive.extractall(self.root, filter="data")

    def tearDown(self):
        self.temporary.cleanup()

    def refresh(self):
        path = self.root / "manifest.json"
        manifest = json.loads(path.read_text())
        for row in manifest["files"]:
            raw = (self.root / row["path"]).read_bytes()
            row.update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        path.write_text(json.dumps(manifest))

    def mutate_filter(self, change):
        phase = json.loads((self.root / "final.json").read_text())
        path = self.root / "commands.json"
        rows = json.loads(path.read_text())
        row = next(item for item in rows if item["id"] == phase["A"]["filters"])
        rules = json.loads(row["stdout"])
        change(rules["nftables"])
        row["stdout"] = json.dumps(rules)
        path.write_text(json.dumps(rows))
        self.refresh()

    def test_real_capture_has_exact_programs_and_frames(self):
        _, report = parse(self.root)
        self.assertEqual(len(report["l2_policies"]), 4)
        self.assertEqual(len(report["probes"]), 11)
        self.assertEqual(report["l2_policies"][0]["payloadLengthRange"], [36, 1500])
        self.assertEqual(report["l2_policies"][0]["declaredLengthPairs"][-1], [1496, 1500])
        self.assertEqual(report["l2_policies"][1]["declaredLengthPairs"][-1], [1496, 1514])
        program = report["l2_policies"][0]["program"]
        for rule in program["rules"][:2]:
            self.assertIn({"ethernetHeaderBytes": {"bytes": 14}}, rule["atoms"])
        self.assertIn({"payloadByteEquals": {"offset": 0, "value": 3}}, program["rules"][0]["atoms"])
        self.assertIn({"payloadBytesRange": {"low": 36, "high": 1500}}, program["rules"][0]["atoms"])
        self.assertEqual(program["rules"][-1], {"atoms": [], "verdict": "deny"})

    def test_frame_reference_resolves_to_original_bytes(self):
        _, report = parse(self.root)
        frame = report["frames"][0]
        raw = read_experiment_raw(self.root, frame["observation"])
        row = json.loads(raw.splitlines()[frame["line"] - 1])
        self.assertEqual(row["bytes"], frame["bytes"])

    def test_vlan_decoder_preserves_outer_header_bytes(self):
        raw = bytes.fromhex("0180c200000302000031000181000007888e03050000")
        record = frame_record(raw)
        self.assertEqual(record["header"]["vlanTags"], [7])
        self.assertEqual(record["header"]["etherType"], 34958)
        self.assertEqual(len(record["headerBytes"]), 18)
        self.assertEqual(bytes(record["headerBytes"] + record["payload"]), raw)

    def test_truncated_vlan_header_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Truncated Ethernet VLAN"):
            frame_record(bytes.fromhex("0180c200000302000031000181000007"))

    def test_original_untagged_capture_remains_readable(self):
        original = self.root / "original"
        original.mkdir()
        with tarfile.open(Path(__file__).parent / "fixtures/l2-admission-public.tar.gz") as archive:
            archive.extractall(original, filter="data")
        _, report = parse(original)
        self.assertEqual(len(report["probes"]), 9)

    def test_changed_auxiliary_tag_is_rejected(self):
        path = self.root / "B-frames.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        tagged = next(row for row in rows if row.get("etherType") == 33024)
        tagged["packetAuxiliary"]["vlanTCI"] += 1
        path.write_text("\n".join(map(json.dumps, rows)) + "\n")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "Reconstructed Ethernet frame differs"):
            parse(self.root)

    def test_missing_auxiliary_metadata_is_rejected(self):
        path = self.root / "B-frames.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]["packetAuxiliary"] = None
        path.write_text("\n".join(map(json.dumps, rows)) + "\n")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "auxiliary metadata"):
            parse(self.root)

    def test_length_mismatch_rejected(self):
        def change(rows):
            rule = next(row["rule"] for row in rows if "rule" in row)
            rule["expr"][4]["match"]["right"]["set"][0]["concat"][1] += 1
        self.mutate_filter(change)
        with self.assertRaisesRegex(ValueError, "match or verdict"):
            parse(self.root)

    def test_missing_length_tuple_rejected(self):
        def change(rows):
            rule = next(row["rule"] for row in rows if "rule" in row)
            rule["expr"][4]["match"]["right"]["set"].pop()
        self.mutate_filter(change)
        with self.assertRaisesRegex(ValueError, "match or verdict"):
            parse(self.root)

    def test_wrong_hook_rejected(self):
        def change(rows):
            next(row["chain"] for row in rows if "chain" in row)["dev"] = "other"
        self.mutate_filter(change)
        with self.assertRaisesRegex(ValueError, "hook or default"):
            parse(self.root)

    def test_unknown_extra_rule_rejected(self):
        def change(rows):
            rows.append(next(row for row in rows if "rule" in row))
        self.mutate_filter(change)
        with self.assertRaisesRegex(ValueError, "rule order"):
            parse(self.root)

    def test_wrong_actor_rejected(self):
        def change(rows):
            next(row["rule"] for row in rows if "rule" in row)["expr"][5]["match"]["right"] += 1
        self.mutate_filter(change)
        with self.assertRaisesRegex(ValueError, "match or verdict"):
            parse(self.root)

    def test_capture_drop_rejected(self):
        path = self.root / "A-frames.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        next(row for row in rows if row.get("recordType") == "captureStatistics")["drops"] = 1
        path.write_text("\n".join(map(json.dumps, rows)) + "\n")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "capture reported drops"):
            parse(self.root)

    def test_unbound_frame_metadata_rejected(self):
        path = self.root / "A-frames.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]["source"] = "000000000000"
        path.write_text("\n".join(map(json.dumps, rows)) + "\n")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            parse(self.root)

    def test_late_filter_installation_rejected(self):
        path = self.root / "observations.json"
        record = json.loads(path.read_text())
        record["filtersBeforeAuthentication"] = False
        path.write_text(json.dumps(record))
        self.refresh()
        with self.assertRaisesRegex(ValueError, "ordering failed"):
            parse(self.root)

    def test_failed_positive_probe_rejected(self):
        path = self.root / "commands.json"
        rows = json.loads(path.read_text())
        record = json.loads((self.root / "observations.json").read_text())
        target = record["probes"][0]["commandObservation"]
        next(row for row in rows if row["id"] == target)["stdout"] = "3 transmitted, 0 received"
        path.write_text(json.dumps(rows))
        self.refresh()
        with self.assertRaisesRegex(ValueError, "Positive traffic failed"):
            parse(self.root)


if __name__ == "__main__":
    unittest.main()
