"""Check clock-source, raw-observation and correction/use bindings."""

import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tdn_evidence.clock import parse, read_experiment_raw
from tdn_evidence.service import EvidenceService


FIXTURE = Path(__file__).parent / "fixtures/clock-use-public.tar.gz"


def refresh(root):
    for directory in [root / "observe-001", root / "configure-001", root / "bootstrap", root]:
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        for row in manifest["files"]:
            row["sha256"] = hashlib.sha256((directory / row["path"]).read_bytes()).hexdigest()
        path.write_text(json.dumps(manifest))


class ClockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        with tarfile.open(FIXTURE) as archive:
            archive.extractall(self.root, filter="data")

    def tearDown(self):
        self.temporary.cleanup()

    def mutate_cases(self, mutation):
        path = self.root / "observe-001/cases.json"
        cases = json.loads(path.read_text())
        mutation(cases)
        path.write_text(json.dumps(cases))
        refresh(self.root)

    def test_four_real_clock_domains(self):
        _, result = parse(self.root)
        self.assertEqual(len(result["clock_uses"]), 4)
        self.assertEqual(len(result["sources"]), 2)
        self.assertEqual(len(result["clock_events"]), 24)
        self.assertEqual(len(result["observations"]), 258)
        self.assertEqual(len({row["clockId"] for row in result["clock_uses"]}), 4)
        self.assertIn("remain unproved", result["coverage"][0]["sourceClock"])

    def test_service_discovery_describes_clock_view(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"store": "store", "networks": [], "saved_experiments": {
                "clock-test": {"parser": "guest-clock-use-v1", "path": str(self.root)}}}))
            service = EvidenceService(config)
            try:
                value = service.describe_capabilities("clock-test")["saved_experiment"]
                self.assertEqual(value["lean_views"], ["clock_synchronization"])
                self.assertIn("clock_events", value["capabilities"])
                self.assertIn("guest clock", value["scope"])
            finally:
                service.pool.shutdown(wait=True)

    def test_changed_normalized_process_is_rejected(self):
        self.mutate_cases(lambda cases: cases[0]["after"].update(charonPid=1))
        with self.assertRaisesRegex(ValueError, "differs from its raw"):
            parse(self.root)

    def test_source_exchange_reference_returns_exact_record(self):
        _, report = parse(self.root)
        for source in report["sources"]:
            packet = next(row for row in report["source_exchanges"] if row["source"] == source["id"])
            expected = (self.root / f"observe-001/{source['id']}-exchanges.jsonl").read_text().splitlines(keepends=True)[0]
            self.assertEqual(read_experiment_raw(self.root, packet["observation"]), expected)
            with self.assertRaisesRegex(ValueError, "do not contain a stderr"):
                read_experiment_raw(self.root, packet["observation"], stderr=True)
        with self.assertRaisesRegex(ValueError, "Unknown clock source exchange"):
            read_experiment_raw(self.root, "ntp:../../elsewhere:0")

    def test_another_guests_correction_is_rejected(self):
        self.mutate_cases(lambda cases: cases[0].update(clockCorrection=cases[1]["clockCorrection"]))
        with self.assertRaisesRegex(ValueError, "another guest"):
            parse(self.root)

    def test_management_source_cannot_be_relabelled(self):
        for phase in ["configure-001", "observe-001"]:
            path = self.root / phase / "time-sources.json"
            sources = json.loads(path.read_text())
            sources[1]["managementNetwork"] = False
            path.write_text(json.dumps(sources))
        refresh(self.root)
        with self.assertRaisesRegex(ValueError, "management role"):
            parse(self.root)

    def test_ntp_request_and_response_must_match(self):
        path = self.root / "observe-001/TC_TIME_RED-exchanges.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        packet = bytearray.fromhex(rows[0]["responseHex"])
        packet[24] ^= 1
        rows[0]["responseHex"] = packet.hex()
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        refresh(self.root)
        with self.assertRaisesRegex(ValueError, "source/request"):
            parse(self.root)

    def test_authentication_failure_reason_is_required(self):
        path = self.root / "observe-001/observations.json"
        record = json.loads(path.read_text())
        for row in record["records"]:
            row["stdout"] = row["stdout"].replace("subject certificate invalid (valid from", "unrelated network failure")
        path.write_text(json.dumps(record))
        refresh(self.root)
        with self.assertRaisesRegex(ValueError, "certificate-time failure"):
            parse(self.root)

    def test_selected_numeric_criterion_is_bound(self):
        self.mutate_cases(lambda cases: cases[0]["selectedCriterion"].update(maximumRemainingCorrectionSeconds=500))
        with self.assertRaisesRegex(ValueError, "criterion differs"):
            parse(self.root)


if __name__ == "__main__":
    unittest.main()
