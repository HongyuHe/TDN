import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp"))
from tdn_evidence.security_assignments import parse

SOURCE = ROOT / "data/extraction/networks/profiles/security-level-assignments-20261111"


class SecurityAssignmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "policy"
        shutil.copytree(SOURCE, self.bundle)
        self.policy = json.loads((self.bundle / "policy.json").read_text())

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        path = self.bundle / "policy.json"
        path.write_text(json.dumps(self.policy))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        for row in manifest["files"]:
            row["sha256"] = hashlib.sha256((self.bundle / row["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_complete_explicit_labels(self):
        _, report = parse(self.bundle)
        self.assertEqual(len(report["assignments"]), 12)
        self.assertTrue(all(r["evidenceStatus"] == "declared" for r in report["assignments"]))
        shared = {r["profileLevel"]: r["assignedLevel"] for r in report["assignments"] if r["profile"] == "shared"}
        self.assertEqual(shared["SECRET_US_ONLY"]["classification"], shared["SECRET_COALITION"]["classification"])
        self.assertNotEqual(shared["SECRET_US_ONLY"]["dissemination"], shared["SECRET_COALITION"]["dissemination"])

    def test_missing_assignment_rejected(self):
        self.policy["profiles"][0]["assignments"].pop()
        self.save()
        with self.assertRaisesRegex(ValueError, "Incomplete Inner"):
            parse(self.bundle)

    def test_missing_dimension_rejected(self):
        del self.policy["profiles"][0]["assignments"][0]["assignedLevel"]["compartments"]
        self.save()
        with self.assertRaisesRegex(ValueError, "four security dimensions"):
            parse(self.bundle)

    def test_unknown_inner_rejected(self):
        self.policy["profiles"][0]["assignments"][0]["innerDevice"] = "UNKNOWN"
        self.save()
        with self.assertRaisesRegex(ValueError, "Incomplete Inner"):
            parse(self.bundle)

    def test_wrong_profile_level_rejected(self):
        self.policy["profiles"][0]["assignments"][0]["profileLevel"] = "S2"
        self.save()
        with self.assertRaisesRegex(ValueError, "Unbound Inner"):
            parse(self.bundle)

    def test_wrong_cohort_rejected(self):
        self.policy["profiles"][0]["snapshotSha256"] = self.policy["profiles"][1]["snapshotSha256"]
        self.save()
        with self.assertRaisesRegex(ValueError, "source hash"):
            parse(self.bundle)

    def test_runtime_or_approval_claim_rejected(self):
        self.policy["realClassificationApproval"] = True
        self.save()
        with self.assertRaisesRegex(ValueError, "experimental policy"):
            parse(self.bundle)

    def test_unrecorded_modification_rejected(self):
        path = self.bundle / "baseline-spec.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            parse(self.bundle)

    def test_duplicate_set_value_rejected(self):
        self.policy["profiles"][0]["assignments"][0]["assignedLevel"]["compartments"] = ["A", "A"]
        self.save()
        with self.assertRaisesRegex(ValueError, "security-label set"):
            parse(self.bundle)


if __name__ == "__main__":
    unittest.main()
