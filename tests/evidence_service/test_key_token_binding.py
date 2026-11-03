"""Verify actual backend versions and the setup preceding a v3 API rejection."""

import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tdn_evidence.key_token_binding import parse


class TokenBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        with tarfile.open(Path(__file__).parent / "fixtures/key-token-binding-public.tar.gz") as archive:
            archive.extractall(self.root, filter="data")

    def tearDown(self):
        self.temporary.cleanup()

    def mutate(self, index, change):
        path = self.root / "binding/observations.json"
        document = json.loads(path.read_text())
        row = document["records"][index]
        value = json.loads(row["stdout"])
        change(value)
        row["stdout"] = json.dumps(value)
        path.write_text(json.dumps(document))
        for directory in [self.root / "binding", self.root]:
            path = directory / "manifest.json"
            manifest = json.loads(path.read_text())
            for item in manifest["files"]:
                item["sha256"] = hashlib.sha256((directory / item["path"]).read_bytes()).hexdigest()
            path.write_text(json.dumps(manifest))

    def test_actual_backend_and_new_interface(self):
        _, report = parse(self.root)
        self.assertEqual(len(report["observations"]), 84)
        self.assertEqual(report["token_interfaces"][0]["backendInterface"]["cryptokiVersion"], [2, 40])

    def test_new_backend_invalidates_legacy_guard(self):
        self.mutate(2, lambda value: value.__setitem__("cryptokiVersion", [3, 0]))
        with self.assertRaisesRegex(ValueError, "legacy interface"):
            parse(self.root)

    def test_changed_backend_binary_rejected(self):
        self.mutate(2, lambda value: value.__setitem__("moduleSha256", "0" * 64))
        with self.assertRaisesRegex(ValueError, "Backend binary changed"):
            parse(self.root)

    def test_failed_session_not_used_as_protection_evidence(self):
        def change(value):
            next(row for row in value["operations"] if row["operation"] == "C_Login")["returnCode"] = 160
        self.mutate(5, change)
        with self.assertRaisesRegex(ValueError, "successful session/key setup"):
            parse(self.root)


if __name__ == "__main__":
    unittest.main()
