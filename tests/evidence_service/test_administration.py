"""Check retained API outcomes and distinguish missing account/session evidence."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tdn_evidence.administration import parse
from tdn_evidence.service import EvidenceService


FIXTURE = Path(__file__).parent / "fixtures/administration-retained"


def refresh(path):
    manifest = path / "manifest.json"
    data = json.loads(manifest.read_text())
    for row in data["files"]:
        row["sha256"] = hashlib.sha256((path / row["path"]).read_bytes()).hexdigest()
    manifest.write_text(json.dumps(data))


class AdministrationTests(unittest.TestCase):
    def test_retained_records_and_missing_fields(self):
        _, report = parse(FIXTURE)
        self.assertEqual(len(report["operations"]), 21)
        self.assertEqual(len(report["audit_events"]), 24)
        self.assertEqual([row["port"] for row in report["listeners"]], [8443, 8443, 8080])
        self.assertTrue(all(row["operationToken"] is None for row in report["operations"]))
        self.assertTrue(next(row for row in report["coverage"] if row["source"] == "role-admin-deploy-v3")["captureError"])

    def test_runtime_source_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "capture"
            shutil.copytree(FIXTURE, root)
            part = root / "role-admin-effective-v3"
            data = json.loads((part / "observations.json").read_text())
            data["records"][-1]["stdout"] = "0" * 64 + "\n"
            (part / "observations.json").write_text(json.dumps(data))
            refresh(part)
            refresh(root)
            with self.assertRaisesRegex(ValueError, "Runtime service hash differs"):
                parse(root)

    def test_unauthorized_success_is_rejected_even_with_consistent_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "capture"
            shutil.copytree(FIXTURE, root)
            part = root / "role-admin-matrix-v3"
            data = json.loads((part / "observations.json").read_text())
            row = next(row for row in data["records"] if row.get("principal") == "auditor" and row.get("path") == "/filter")
            row["observed_result"] = 200
            row["stdout"] = row["stdout"].replace("HTTP_STATUS=403", "HTTP_STATUS=200")
            (part / "observations.json").write_text(json.dumps(data))
            refresh(part)
            refresh(root)
            with self.assertRaisesRegex(ValueError, "API outcome differs"):
                parse(root)

    def test_nested_manifest_is_part_of_aggregate_integrity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "capture"
            shutil.copytree(FIXTURE, root)
            path = root / "role-admin-effective-v3/manifest.json"
            path.write_text(path.read_text() + " ")
            with self.assertRaisesRegex(ValueError, "file hash mismatch"):
                parse(root)

    def test_service_queries_and_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.json"
            config.write_text(json.dumps({"store": "store", "saved_experiments": {
                "admin": {"path": str(FIXTURE.resolve()), "parser": "administration-observations-v1"}}}))
            service = EvidenceService(config)
            try:
                self.assertEqual(service.query_evidence("admin", "operations")["total"], 21)
                self.assertEqual(service.query_evidence("admin", "listeners")["total"], 3)
                first = service.prepare_lean_bundle("admin", "administration_observations")
                self.assertEqual(first, service.prepare_lean_bundle("admin", "administration_observations"))
            finally:
                service.pool.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
