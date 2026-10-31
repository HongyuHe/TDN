"""Reject unsupported key-server and CKN claims in the final public EAP records."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_macsec_key_servers import parse
from validate_evidence import EvidenceError


class KeyServerImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = []
        for name in ["eap-tls-forward-v18", "eap-tls-reverse-v18"]:
            target = Path(self.temp.name) / name
            shutil.copytree(ROOT / "artifacts/snapshots/2026-10-24T014455Z" / name, target)
            self.paths.append(target)

    def tearDown(self):
        self.temp.cleanup()

    def read(self, name):
        return json.loads((self.paths[0] / name).read_text())

    def save(self, name, data):
        path = self.paths[0] / name
        path.write_text(json.dumps(data))
        manifest = self.read("manifest.json")
        row = next(row for row in manifest["files"] if row["path"] == name)
        row.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        (self.paths[0] / "manifest.json").write_text(json.dumps(manifest))

    def change_peer_log(self, change):
        rows = self.read("commands.json")
        row = next(row for row in rows if row["command"][0] == "cat" and Path(row["command"][-1]).name == "P0.log")
        row["stdout"] = change(row["stdout"])
        self.save("commands.json", rows)

    def test_both_role_arrangements(self):
        cases = parse(self.paths)
        self.assertEqual([[row["priority"] for row in case["peers"]] for case in cases], [[0, 1], [1, 0]])
        self.assertTrue(all(row["ckn_bytes"] == 16 and not row["ckn_value_exported"]
                            for case in cases for row in case["peers"]))

    def test_short_reported_ckn(self):
        self.change_peer_log(lambda log: log.replace("KaY: CKN - hexdump(len=16)", "KaY: CKN - hexdump(len=8)"))
        with self.assertRaisesRegex(EvidenceError, "minimum"):
            parse(self.paths)

    def test_unexpected_local_priority(self):
        self.change_peer_log(lambda log: log.replace("priority=0", "priority=2"))
        with self.assertRaisesRegex(EvidenceError, "Local priority"):
            parse(self.paths)

    def test_site_role_mismatch(self):
        evidence = self.read("evidence.json")
        next(row for row in evidence["devices"] if row["id"] == "P0")["site"] = "remote"
        self.save("evidence.json", evidence)
        with self.assertRaisesRegex(EvidenceError, "Declared sites"):
            parse(self.paths)

    def test_missing_ckn_length(self):
        self.change_peer_log(lambda log: "\n".join(line for line in log.splitlines() if "KaY: CKN - hexdump" not in line))
        with self.assertRaisesRegex(EvidenceError, "reported CKN"):
            parse(self.paths)

    def test_repeated_arrangement_is_not_two_distinct_cases(self):
        with self.assertRaisesRegex(EvidenceError, "Both distinct"):
            parse([self.paths[0], self.paths[0]])

    def test_missing_peer_device(self):
        evidence = self.read("evidence.json")
        evidence["devices"] = [row for row in evidence["devices"] if row["id"] != "P1"]
        self.save("evidence.json", evidence)
        with self.assertRaisesRegex(EvidenceError, "peer inventory"):
            parse(self.paths)


if __name__ == "__main__":
    unittest.main()
