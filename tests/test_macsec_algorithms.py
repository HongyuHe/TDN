"""Mutate the retained public source and vector bindings without network access."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_macsec_algorithms import parse, parse_vectors, parse_bindings

BASE = ROOT / "artifacts/snapshots/2026-10-24T014455Z"


class MACsecAlgorithmTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "vectors"
        shutil.copytree(BASE / "hostap-kdf-vectors-v3", self.bundle)

    def tearDown(self):
        self.temp.cleanup()

    def update(self, path, value):
        path.write_text(json.dumps(value) if not isinstance(value, str) else value)
        manifest = json.loads((path.parent / "manifest.json").read_text()) if path.parent == self.bundle else json.loads((self.bundle / "manifest.json").read_text())
        for row in manifest["files"]:
            target = self.bundle / row["path"]
            row["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
            row["bytes"] = target.stat().st_size
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def observations(self):
        return json.loads((self.bundle / "observations.json").read_text())

    def test_all_final_ports_and_vectors(self):
        result = parse([BASE / "eap-tls-forward-v18", BASE / "eap-tls-reverse-v18"],
                       BASE / "hostap-kdf-bindings-v4", BASE / "final-hostap-runtime-v4", self.bundle)
        self.assertEqual(len(result["devices"]), 4)
        self.assertEqual(len(result["finite_vectors"]["results"]), 12)

    def test_raw_vector_mismatch(self):
        value = self.observations()
        value["records"][2]["stdout"] = "00" * 16
        self.update(self.bundle / "observations.json", value)
        with self.assertRaisesRegex(ValueError, "raw vector output mismatch"):
            parse_vectors(self.bundle)

    def test_changed_vector_command(self):
        value = self.observations()
        value["records"][2]["command"][-1] = "32"
        self.update(self.bundle / "observations.json", value)
        with self.assertRaisesRegex(ValueError, "published input"):
            parse_vectors(self.bundle)

    def test_omitted_vector(self):
        value = self.observations()
        value["records"].pop()
        self.update(self.bundle / "observations.json", value)
        with self.assertRaisesRegex(ValueError, "twelve-vector"):
            parse_vectors(self.bundle)

    def test_failed_vector(self):
        value = self.observations()
        value["records"][2]["returncode"] = 1
        self.update(self.bundle / "observations.json", value)
        with self.assertRaisesRegex(ValueError, "failed recorded"):
            parse_vectors(self.bundle)

    def test_empty_error_is_failure(self):
        value = self.observations()
        value["error"] = ""
        self.update(self.bundle / "observations.json", value)
        with self.assertRaisesRegex(ValueError, "explicit success"):
            parse_vectors(self.bundle)

    def test_changed_published_expected(self):
        value = json.loads((self.bundle / "vectors.json").read_text())
        value[0][-1] = "00" * 16
        self.update(self.bundle / "vectors.json", value)
        with self.assertRaisesRegex(ValueError, "published vector inventory"):
            parse_vectors(self.bundle)

    def test_changed_harness(self):
        path = self.bundle / "build/vector-harness.c"
        self.update(path, path.read_text().replace('if(r)return 3;', 'if(r)return 0;'))
        with self.assertRaisesRegex(ValueError, "harness/CMAC"):
            parse_vectors(self.bundle)

    def test_changed_derivation_source(self):
        path = self.bundle / "runtime-ieee802_1x_key.c"
        self.update(path, path.read_text() + "\n/* changed */\n")
        with self.assertRaisesRegex(ValueError, "reviewed source"):
            parse_vectors(self.bundle)


if __name__ == "__main__":
    unittest.main()
