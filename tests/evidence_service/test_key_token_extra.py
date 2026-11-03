"""Check private-derived behavior and complete versioned interface inventory."""

import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tdn_evidence.key_token_extra import parse, read_experiment_raw


class TokenExtraTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        with tarfile.open(Path(__file__).parent / "fixtures/key-token-extra-public.tar.gz") as archive:
            archive.extractall(self.root, filter="data")

    def tearDown(self):
        self.temporary.cleanup()

    def mutate(self, change):
        path = self.root / "extra/observations.json"
        document = json.loads(path.read_text())
        row = document["records"][1]
        value = json.loads(row["stdout"])
        change(value)
        row["stdout"] = json.dumps(value)
        path.write_text(json.dumps(document))
        for directory in [self.root / "extra", self.root]:
            path = directory / "manifest.json"
            manifest = json.loads(path.read_text())
            for item in manifest["files"]:
                item["sha256"] = hashlib.sha256((directory / item["path"]).read_bytes()).hexdigest()
            path.write_text(json.dumps(manifest))

    def test_actual_digest_and_interfaces(self):
        _, report = parse(self.root)
        self.assertEqual(len(report["observations"]), 72)
        self.assertEqual(report["token_api"][0]["record"]["digestBytes"], 48)
        self.assertIn("C_GetInterfaceList", read_experiment_raw(self.root, "extra:extra-api-0001"))

    def test_missing_new_interface_rejected(self):
        self.mutate(lambda value: value["api"]["interfaces"].pop(0))
        with self.assertRaisesRegex(ValueError, "interface count"):
            parse(self.root)

    def test_replaced_function_rejected(self):
        self.mutate(lambda value: value["api"]["interfaces"][0]["callableFunctions"].__setitem__(-1, "C_Unknown"))
        with self.assertRaisesRegex(ValueError, "interface table differs"):
            parse(self.root)

    def test_digest_cannot_be_silently_classified_as_rejected(self):
        self.mutate(lambda value: value.__setitem__("digestKeyCode", 84))
        with self.assertRaisesRegex(ValueError, "API outcome"):
            parse(self.root)

    def test_key_identity_mismatch_rejected(self):
        self.mutate(lambda value: value.__setitem__("publicSPKISha256", "0" * 64))
        with self.assertRaisesRegex(ValueError, "key/certificate identity differs"):
            parse(self.root)

    def test_return_code_summary_must_match_call(self):
        def change(value):
            next(row for row in value["operations"] if row["operation"] == "C_DeriveKey")["returnCode"] = 0
        self.mutate(change)
        with self.assertRaisesRegex(ValueError, "summary and actual return code differ"):
            parse(self.root)


if __name__ == "__main__":
    unittest.main()
