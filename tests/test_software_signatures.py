"""Check signing import mutations by reading temporary copies only."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_software_signatures import parse, public_key_bytes
from validate_evidence import EvidenceError


class SoftwareSignatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "software-signing-v3"
        shutil.copytree(ROOT / "artifacts/snapshots/2026-10-24T014455Z/software-signing-v3", self.root)

    def tearDown(self):
        self.temp.cleanup()

    def replace(self, name, data):
        (self.root / name).write_bytes(data)
        path = self.root / "manifest.json"
        manifest = json.loads(path.read_text())
        row = next(row for row in manifest["files"] if row["path"] == name)
        row["sha256"] = hashlib.sha256(data).hexdigest()
        path.write_text(json.dumps(manifest))

    def change_observations(self, update):
        data = json.loads((self.root / "observations.json").read_text())
        update(data)
        self.replace("observations.json", json.dumps(data).encode())

    def test_retained_algorithm_and_scope(self):
        result = parse(self.root)
        self.assertEqual(result["algorithm"], "ML-DSA-87")
        self.assertFalse(result["whole_RG073_established"])

    def test_altered_algorithm_identifier(self):
        pem = (self.root / "publisher.pub").read_text()
        der = base64.b64decode("".join(pem.splitlines()[1:-1]))
        altered = der.replace(bytes.fromhex("0609608648016503040313"), bytes.fromhex("0609608648016503040312"), 1)
        self.replace("publisher.pub", b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(altered) + b"-----END PUBLIC KEY-----\n")
        with self.assertRaisesRegex(EvidenceError, "not parameter-free ML-DSA-87"):
            parse(self.root)

    def test_public_dump_does_not_match_key(self):
        self.change_observations(lambda data: data["records"][8].update(stdout=data["records"][8]["stdout"].replace("08:ef", "09:ef", 1)))
        with self.assertRaisesRegex(EvidenceError, "bytes differ"):
            parse(self.root)

    def test_wrong_signing_key(self):
        self.change_observations(lambda data: data["records"][4]["command"].__setitem__(-5, "/private/other.key"))
        with self.assertRaisesRegex(EvidenceError, "operation or key/manifest path"):
            parse(self.root)

    def test_changed_payload_mount(self):
        self.change_observations(lambda data: data["records"][5]["command"].__setitem__(10, "/other:/payload/twinet-linux:ro"))
        with self.assertRaisesRegex(EvidenceError, "loader command/outcome"):
            parse(self.root)

    def test_rejection_code_missing(self):
        self.change_observations(lambda data: data["records"][6].update(returncode=0))
        with self.assertRaisesRegex(EvidenceError, "loader command/outcome"):
            parse(self.root)

    def test_unreviewed_source(self):
        name = "verified_loader.py"
        self.replace(name, (self.root / name).read_bytes() + b"\n")
        with self.assertRaisesRegex(EvidenceError, "Unreviewed"):
            parse(self.root)

    def test_collection_error(self):
        self.change_observations(lambda data: data.update(error=""))
        with self.assertRaisesRegex(EvidenceError, "collection reports"):
            parse(self.root)

    def test_reversed_command_order(self):
        self.change_observations(lambda data: data["records"].__setitem__(slice(2, 4), list(reversed(data["records"][2:4]))))
        with self.assertRaisesRegex(EvidenceError, "order changed"):
            parse(self.root)

    def test_truncated_der(self):
        with self.assertRaises(EvidenceError):
            public_key_bytes(b"-----BEGIN PUBLIC KEY-----\nMAIw\n-----END PUBLIC KEY-----\n")


if __name__ == "__main__":
    unittest.main()
