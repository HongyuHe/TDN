"""Exercise token-operation provenance and gateway/backend isolation checks."""

import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tdn_evidence.key_token import parse, read_experiment_raw


class KeyTokenTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        with tarfile.open(Path(__file__).parent / "fixtures/key-token-public.tar.gz") as archive:
            archive.extractall(self.root, filter="data")

    def tearDown(self):
        self.temporary.cleanup()

    def rehash(self, directory):
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        for entry in manifest["files"]:
            entry["sha256"] = hashlib.sha256((directory / entry["path"]).read_bytes()).hexdigest()
        path.write_text(json.dumps(manifest))

    def mutate(self, phase, predicate, change):
        path = self.root / phase / "observations.json"
        document = json.loads(path.read_text())
        row = next(row for row in document["records"] if predicate(row))
        change(row)
        path.write_text(json.dumps(document))
        for directory in [self.root / phase, self.root]:
            self.rehash(directory)

    def test_current_helper_can_be_used_for_all_phases(self):
        helper = (self.root / "observe/token_operations.py").read_bytes()
        for phase in ["bootstrap", "configure"]:
            (self.root / phase / "token_operations.py").write_bytes(helper)
            self.rehash(self.root / phase)
        self.rehash(self.root)
        _, report = parse(self.root)
        self.assertEqual(len(report["token_keys"]), 2)

    def change_exercise(self, change):
        def transform(row):
            value = json.loads(row["stdout"])
            change(value)
            row["stdout"] = json.dumps(value)
        self.mutate("observe", lambda row: row["id"] == "observe-0000", transform)

    def test_actual_tokens_and_traffic(self):
        _, report = parse(self.root)
        self.assertEqual(len(report["token_keys"]), 2)
        self.assertEqual(len(report["observations"]), 63)
        self.assertIn("CKR_KEY_UNEXTRACTABLE", read_experiment_raw(self.root, "observe:observe-0000"))

    def test_uninitialized_copy_is_not_protection_evidence(self):
        def change(value):
            next(row for row in value["attempts"] if row["operation"] == "copy-private-key")["returnCode"] = 400
        self.change_exercise(change)
        with self.assertRaisesRegex(ValueError, "expected protection rejection"):
            parse(self.root)

    def test_unsupported_wrap_is_not_protection_evidence(self):
        def change(value):
            next(row for row in value["attempts"] if row["operation"] == "wrap-private-key")["returnCode"] = 112
        self.change_exercise(change)
        with self.assertRaisesRegex(ValueError, "expected protection rejection"):
            parse(self.root)

    def test_certificate_mismatch_rejected(self):
        self.change_exercise(lambda value: value.__setitem__("certificateSha256", "0" * 64))
        with self.assertRaisesRegex(ValueError, "certificate binding differs"):
            parse(self.root)

    def test_extra_key_alias_rejected(self):
        self.change_exercise(lambda value: value.__setitem__("privateKeyCountBeforeAndAfter", [1, 2]))
        with self.assertRaisesRegex(ValueError, "object inventory"):
            parse(self.root)

    def test_exportable_key_rejected(self):
        self.change_exercise(lambda value: value["attributes"].__setitem__("CKA_EXTRACTABLE", True))
        with self.assertRaisesRegex(ValueError, "capability enabled"):
            parse(self.root)

    def test_backend_storage_mounted_at_gateway_rejected(self):
        def change(row):
            value = json.loads(row["stdout"])
            storage = next(mount for mount in value[1]["Mounts"] if mount["Destination"] == "/token")
            value[0]["Mounts"].append(storage)
            row["stdout"] = json.dumps(value)
        self.mutate("observe", lambda row: row["id"] == "observe-0016", change)
        with self.assertRaisesRegex(ValueError, "protected host storage"):
            parse(self.root)

    def test_gateway_host_pid_namespace_rejected(self):
        def change(row):
            value = json.loads(row["stdout"])
            value[0]["HostConfig"]["PidMode"] = "host"
            row["stdout"] = json.dumps(value)
        self.mutate("observe", lambda row: row["id"] == "observe-0016", change)
        with self.assertRaisesRegex(ValueError, "host process namespace"):
            parse(self.root)


if __name__ == "__main__":
    unittest.main()
