"""Reject gaps, partial copies, changed journals, and mismatched audit observations."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_audit_offload import PINS, parse
from validate_evidence import EvidenceError


class AuditOffloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        for name in {p.split("/")[0] for p in PINS}:
            shutil.copytree(ROOT / "artifacts/snapshots/2026-10-24T014455Z" / name, self.base / name)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, bundle, transform):
        path = self.base / bundle / "observations.json"
        data = json.loads(path.read_text())
        transform(data)
        path.write_text(json.dumps(data))
        m = path.parent / "manifest.json"
        manifest = json.loads(m.read_text())
        row = next(row for row in manifest["files"] if row["path"] == "observations.json")
        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        m.write_text(json.dumps(manifest))

    def mutate_both_journals(self, transform):
        def change(data):
            for row in data["records"]:
                if "label" in row:
                    transform(row)
        self.change("audit-collector-reliability-v8", change)

    def test_complete_copy_and_restart(self):
        result = parse(self.base)
        self.assertEqual(result["source_bytes"], 136535)
        self.assertEqual(len(result["journal"]), 3)
        self.assertFalse(result["whole_RG062_established"])

    def test_gap_in_both_captures(self):
        self.mutate_both_journals(lambda row: row["records"][1].update(offset=65537))
        with self.assertRaisesRegex(EvidenceError, "gap, overlap"):
            parse(self.base)

    def test_prefix_only_is_not_whole_source(self):
        self.mutate_both_journals(lambda row: row["records"].pop())
        with self.assertRaisesRegex(EvidenceError, "complete cursor changed"):
            parse(self.base)

    def test_changed_restart_hash(self):
        self.change("audit-collector-reliability-v8", lambda data:
                    data["records"][1].update(journal_sha256="0" * 64))
        with self.assertRaisesRegex(EvidenceError, "Journal changed"):
            parse(self.base)

    def test_missing_marker(self):
        self.mutate_both_journals(lambda row: row.update(actual_audit_markers=[]))
        with self.assertRaisesRegex(EvidenceError, "marker absent"):
            parse(self.base)

    def test_wrong_authenticated_device(self):
        self.mutate_both_journals(lambda row: row["records"][0].update(peer_cn="another-device"))
        with self.assertRaisesRegex(EvidenceError, "identity or protected-channel"):
            parse(self.base)

    def test_wrong_source_guest(self):
        self.change("audit-source-drain-v10", lambda data:
                    data["records"][0]["command"].__setitem__(6, "22353"))
        with self.assertRaisesRegex(EvidenceError, "Wrong source guest"):
            parse(self.base)

    def test_failed_collection_is_not_accepted(self):
        self.change("audit-source-drain-v10", lambda data: data.update(error=""))
        with self.assertRaisesRegex(EvidenceError, "Incomplete collection"):
            parse(self.base)

    def test_different_source_copy(self):
        def change(data):
            row = data["records"][2]
            row["stdout"] = row["stdout"].replace("fcc23fcb5b29655ce527561dba53038b8da73a66ea1fefa2f073bd4d206d4a6f", "0" * 64)
        self.change("audit-source-drain-v10", change)
        with self.assertRaisesRegex(EvidenceError, "source copy or complete cursor changed"):
            parse(self.base)


    def test_initial_copy_from_other_guest_is_rejected(self):
        self.change("audit-protected-offload-v5", lambda data:
                    next(row for row in data["records"] if row["id"] == "offload-0012")["command"].__setitem__(8, "22353"))
        with self.assertRaisesRegex(EvidenceError, "Wrong source guest"):
            parse(self.base)

    def test_initial_ack_from_other_guest_is_rejected(self):
        self.change("audit-protected-offload-v5", lambda data:
                    next(row for row in data["records"] if row["id"] == "offload-0013")["command"].__setitem__(8, "22353"))
        with self.assertRaisesRegex(EvidenceError, "Wrong source guest"):
            parse(self.base)

    def test_final_hash_command_must_read_exact_file(self):
        self.change("audit-source-drain-v10", lambda data:
                    data["records"][2]["command"].__setitem__(-1, "printf unchanged"))
        with self.assertRaisesRegex(EvidenceError, "final source readback"):
            parse(self.base)

    def test_original_hash_command_must_read_exact_file(self):
        self.change("audit-protected-offload-v5", lambda data:
                    next(row for row in data["records"] if row["id"] == "offload-0017")["command"].__setitem__(-1, "printf unchanged"))
        with self.assertRaisesRegex(EvidenceError, "original source hash"):
            parse(self.base)


if __name__ == "__main__":
    unittest.main()
