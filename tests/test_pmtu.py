import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_pmtu import parse

SOURCE = ROOT / "artifacts/snapshots/2026-10-24T014455Z/IPv6-PMTU-v4"


class PMTUImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(SOURCE, self.bundle)

    def tearDown(self):
        self.temp.cleanup()

    def load(self, name):
        return json.loads((self.bundle / name).read_text())

    def save(self, name, value):
        (self.bundle / name).write_text(json.dumps(value))
        manifest = self.load("manifest.json")
        for row in manifest["files"]:
            row["sha256"] = hashlib.sha256((self.bundle / row["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_real_transition(self):
        result = parse(self.bundle)
        self.assertEqual((result["effective_ip_limit"], result["black_mtu"]), (1326, 1400))

    def test_wrong_quote_rejected(self):
        rows = self.load("Red-source.json")
        for row in rows["records"]:
            if row.get("icmpv6_type") == 2:
                row["quoted_header"]["source"] = "fd72:9::2"
        self.save("Red-source.json", rows)
        with self.assertRaisesRegex(ValueError, "different source flow"):
            parse(self.bundle)

    def test_socket_limit_without_matching_ptb_rejected(self):
        sender = self.load("sender.json")
        sender["final_path_mtu"] = 1400
        self.save("sender.json", sender)
        with self.assertRaisesRegex(ValueError, "socket limit"):
            parse(self.bundle)

    def test_wrong_received_payload_rejected(self):
        receiver = self.load("receiver.json")
        receiver["received"][0]["sha256"] = "0" * 64
        self.save("receiver.json", receiver)
        with self.assertRaisesRegex(ValueError, "payload"):
            parse(self.bundle)

    def test_unbound_mtu_rejected(self):
        before = self.load("before.json")
        before["R"]["interfaces"]["value"] = before["R"]["interfaces"]["value"].replace('"mtu":1400', '"mtu":1300')
        self.save("before.json", before)
        with self.assertRaisesRegex(ValueError, "differs from raw"):
            parse(self.bundle)

    def test_changed_icv_configuration_rejected(self):
        before = self.load("before.json")
        raw = before["IA"]["xfrm"]
        raw["value"] = raw["value"].replace("<<Keys hidden>> 128", "<<Keys hidden>> 96")
        commands = self.load("commands.json")
        next(r for r in commands if r["id"] == raw["observation_id"])["stdout"] = raw["value"]
        self.save("before.json", before)
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "overhead"):
            parse(self.bundle)


if __name__ == "__main__":
    unittest.main()
