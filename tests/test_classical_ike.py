"""Check proposal alternatives and reject inconsistent public credential bindings."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_classical_ike import parse, parse_offers
from validate_evidence import EvidenceError

SNAPSHOTS = ROOT / "data/snapshots/2026-10-24T014455Z"
BASELINE = SNAPSHOTS / "native-baseline-20261024T015000Z"
PUBLIC = SNAPSHOTS / "native-public-auth-bindings-20261024T020200Z"


class ClassicalProposalTests(unittest.TestCase):
    def test_all_transform_combinations(self):
        rows = parse_offers("aes256gcm16-prfsha384-prfsha512-ecp384-modp3072-modp4096")
        self.assertEqual(len(rows), 6)
        self.assertEqual({row["integrity"] for row in rows}, {"sha384", "sha512"})
        self.assertEqual({row["establishment"] for row in rows}, {"ecdhP384", "dh3072", "dh4096"})

    def test_every_comma_separated_offer_checked(self):
        with self.assertRaisesRegex(ValueError, "unapproved"):
            parse_offers("aes256gcm16-prfsha384-ecp384,aes128gcm16-prfsha384-ecp384")

    def test_weak_hash_rejected(self):
        with self.assertRaisesRegex(ValueError, "unapproved"):
            parse_offers("aes256gcm16-prfsha256-ecp384")

    def test_missing_exchange_rejected(self):
        with self.assertRaisesRegex(EvidenceError, "Incomplete"):
            parse_offers("aes256gcm16-prfsha384")

    def test_default_rejected(self):
        with self.assertRaisesRegex(ValueError, "unapproved"):
            parse_offers("default")


class ClassicalBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.public = Path(self.temp.name) / "public-bindings"
        shutil.copytree(PUBLIC, self.public)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, name, update):
        path = self.public / name
        data = json.loads(path.read_text())
        update(data)
        path.write_text(json.dumps(data))
        manifest_path = self.public / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        row = next(row for row in manifest["files"] if row["path"] == name)
        row.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        manifest_path.write_text(json.dumps(manifest))

    def test_complete_four_inner_bindings(self):
        result = parse(BASELINE, self.public)
        self.assertEqual(result["checked_inner_inventory"], 4)
        self.assertEqual(result["complete_gateway_inventory"], 8)
        self.assertFalse(result["whole_RG019_established"])

    def test_missing_device(self):
        self.change("bindings.json", lambda data: data["devices"].pop(0))
        with self.assertRaisesRegex(EvidenceError, "Complete Inner"):
            parse(BASELINE, self.public)

    def test_wrong_peer(self):
        self.change("bindings.json", lambda data: data["devices"][0].update(peer_device_id="absent"))
        with self.assertRaisesRegex(EvidenceError, "Peer certificate"):
            parse(BASELINE, self.public)

    def test_wrong_local_identity(self):
        self.change("bindings.json", lambda data: data["devices"][0].update(configured_local_id="another-device"))
        with self.assertRaisesRegex(EvidenceError, "subject mismatch"):
            parse(BASELINE, self.public)

    def test_wrong_public_key_digest(self):
        self.change("bindings.json", lambda data: data["devices"][0].update(own_public_key_spki_sha256="0" * 64))
        with self.assertRaisesRegex(EvidenceError, "Public-key identity"):
            parse(BASELINE, self.public)

    def test_later_configuration_changed(self):
        self.change("raw/auth-0000.json", lambda data: data.update(stdout=data["stdout"].replace("ecp384", "ecp256")))
        with self.assertRaisesRegex(EvidenceError, "configuration differs"):
            parse(BASELINE, self.public)

    def test_certificate_capture_wrong_namespace(self):
        self.change("raw/auth-0002.json", lambda data: data["command"].__setitem__(2, "another-device"))
        with self.assertRaisesRegex(EvidenceError, "command/device mismatch"):
            parse(BASELINE, self.public)


if __name__ == "__main__":
    unittest.main()
