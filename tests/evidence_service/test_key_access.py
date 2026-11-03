"""Check daemon identity, public key bindings and administration-audit provenance."""

import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tdn_evidence.key_access import parse, read_experiment_raw


class KeyAccessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        with tarfile.open(Path(__file__).parent / "fixtures/key-interface-public.tar.gz") as archive:
            archive.extractall(self.root, filter="data")

    def tearDown(self):
        self.temporary.cleanup()

    def mutate(self, kind, transform):
        path = self.root / "observations.json"
        document = json.loads(path.read_text())
        row = next(row for row in document["records"] if row["kind"] == kind)
        transform(row)
        path.write_text(json.dumps(document))
        path = self.root / "manifest.json"
        manifest = json.loads(path.read_text())
        for item in manifest["files"]:
            item["sha256"] = hashlib.sha256((self.root / item["path"]).read_bytes()).hexdigest()
        path.write_text(json.dumps(manifest))

    def test_daemons_keys_and_missing_ssh_are_exposed(self):
        _, report = parse(self.root)
        self.assertEqual(len(report["key_access"]), 2)
        self.assertEqual(len(report["observations"]), 39)
        for device in report["key_access"]:
            self.assertGreater(len(device["daemon"]["modules"]), 1)
            self.assertEqual(device["unavailable"][0]["kind"], "ssh-effective-configuration")

    def test_raw_observation_read(self):
        _, report = parse(self.root)
        item = report["observations"][0]
        self.assertEqual(read_experiment_raw(self.root, item["id"]), item["record"]["stdout"])

    def test_mismatched_daemon_pid_rejected(self):
        def change(row):
            value = json.loads(row["stdout"])
            value["processes"][0]["pid"] += 1
            row["stdout"] = json.dumps(value)
        self.mutate("daemon-process", change)
        with self.assertRaisesRegex(ValueError, "status PID differs"):
            parse(self.root)

    def test_mismatched_public_key_rejected(self):
        def change(row):
            value = json.loads(row["stdout"])
            value[0]["publicSPKISha256"] = "0" * 64
            row["stdout"] = json.dumps(value)
        self.mutate("public-key-bindings", change)
        with self.assertRaisesRegex(ValueError, "no matching certificate"):
            parse(self.root)

    def test_wrong_container_command_rejected(self):
        self.mutate("container-boundary:V31B_I_A1", lambda row: row["command"].__setitem__(-1, "other"))
        with self.assertRaisesRegex(ValueError, "inspection command differs"):
            parse(self.root)


if __name__ == "__main__":
    unittest.main()
