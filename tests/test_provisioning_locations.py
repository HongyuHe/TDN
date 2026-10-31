"""Reject changed execution locations and broken certificate-command dependencies."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_provisioning_locations import parse
from validate_evidence import EvidenceError


class ProvisioningLocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = []
        for name in ["eap-tls-forward-v18", "eap-tls-reverse-v18"]:
            path = Path(self.temp.name) / name
            shutil.copytree(ROOT / "artifacts/snapshots/2026-10-24T014455Z" / name, path)
            self.paths.append(path)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, transform):
        path = self.paths[0] / "commands.json"
        rows = json.loads(path.read_text())
        transform(rows)
        path.write_text(json.dumps(rows))
        manifest_path = self.paths[0] / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        row = next(row for row in manifest["files"] if row["path"] == "commands.json")
        row.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        manifest_path.write_text(json.dumps(manifest))

    def test_actual_worker_generation(self):
        data = parse(self.paths)
        self.assertEqual([row["executor"] for row in data["records"]], ["worker", "worker"])
        self.assertFalse(data["whole_RG048_established"])

    def test_changed_device_location(self):
        self.change(lambda rows: rows[39].update(device_id="P1"))
        with self.assertRaisesRegex(EvidenceError, "execution location changed"):
            parse(self.paths)

    def test_csr_uses_another_key(self):
        self.change(lambda rows: rows[40]["command"].__setitem__(4, "/another/key"))
        with self.assertRaisesRegex(EvidenceError, "CSR does not use"):
            parse(self.paths)

    def test_signing_uses_another_csr(self):
        self.change(lambda rows: rows[41]["command"].__setitem__(4, "/another/request"))
        with self.assertRaisesRegex(EvidenceError, "Signing does not use"):
            parse(self.paths)

    def test_failed_generation(self):
        self.change(lambda rows: rows[39].update(returncode=1))
        with self.assertRaisesRegex(EvidenceError, "operation failed"):
            parse(self.paths)

    def test_request_precedes_generation(self):
        self.change(lambda rows: rows[40].update(started_at=rows[39]["started_at"]))
        with self.assertRaisesRegex(EvidenceError, "time order changed"):
            parse(self.paths)

    def test_duplicate_key_generation(self):
        def duplicate(rows):
            copy = dict(rows[39])
            copy["id"] = "extra-generation"
            rows.append(copy)
        self.change(duplicate)
        with self.assertRaisesRegex(EvidenceError, "ambiguous provisioning"):
            parse(self.paths)


if __name__ == "__main__":
    unittest.main()
