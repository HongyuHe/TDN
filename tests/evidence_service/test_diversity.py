"""Check gateway identity binding and separate historical observation phases."""

import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tdn_evidence.diversity import parse, read_experiment_raw


class DiversityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        with tarfile.open(Path(__file__).parent / "fixtures/os-provider-public.tar.gz") as archive:
            archive.extractall(self.root, filter="data")

    def tearDown(self):
        self.temporary.cleanup()

    def mutate(self, phase, transform):
        context = json.loads((self.root / "context.json").read_text())
        folder = self.root / next(row["path"] for row in context["phases"] if row["id"] == phase)
        path = folder / "observations.json"
        document = json.loads(path.read_text())
        transform(document)
        path.write_text(json.dumps(document))
        for directory in [folder, self.root]:
            path = directory / "manifest.json"
            manifest = json.loads(path.read_text())
            for row in manifest["files"]:
                row["sha256"] = hashlib.sha256((directory / row["path"]).read_bytes()).hexdigest()
            path.write_text(json.dumps(manifest))

    def test_distinct_families_and_bound_inner_interfaces(self):
        _, report = parse(self.root)
        self.assertEqual(len(report["gateway_identities"]), 4)
        self.assertEqual({row["osFamily"] for row in report["gateway_identities"]}, {"FreeBSD", "Linux"})
        self.assertEqual(len(report["phases"]), 6)
        for row in report["gateway_identities"]:
            if row["role"] == "inner":
                self.assertEqual(len(row["boundInterfaces"]), 2)
                self.assertIn("daemonPID", row["unavailable"])
            else:
                self.assertGreater(row["daemonNamespacePID"], 0)

    def test_raw_reference_preserves_original_record(self):
        _, report = parse(self.root)
        for row in report["observations"][:2]:
            self.assertEqual(read_experiment_raw(self.root, row["id"]), row["record"].get("stdout", ""))
        with self.assertRaisesRegex(ValueError, "Unknown diversity"):
            read_experiment_raw(self.root, "unknown:0")

    def test_wrong_inner_family_rejected(self):
        self.mutate("inner", lambda document: [row.update(stdout="Linux fake") for row in document["records"]
                                               if row["command"][-1] == "uname -a"])
        with self.assertRaisesRegex(ValueError, "Inner family"):
            parse(self.root)

    def test_unbound_inner_address_rejected(self):
        self.mutate("inner", lambda document: [row.update(stdout=row["stdout"].replace("10.1.1.1", "10.9.9.9"))
                                               for row in document["records"] if row["command"][-1] == "ifconfig -a"])
        with self.assertRaisesRegex(ValueError, "uniquely bind"):
            parse(self.root)

    def test_changed_outer_provider_rejected(self):
        self.mutate("outer", lambda document: [row.update(stdout=row["stdout"].replace("openssl", "botan"))
                                               for row in document["records"] if row["command"][-1] == "--stats"])
        with self.assertRaisesRegex(ValueError, "Outer loaded provider"):
            parse(self.root)

    def test_supplement_failure_remains_visible(self):
        self.mutate("startup", lambda document: document.update(error="new failure"))
        _, report = parse(self.root)
        self.assertEqual(next(row for row in report["phases"] if row["id"] == "startup")["error"], "new failure")


if __name__ == "__main__":
    unittest.main()
