import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_dns_hardening import parse

SOURCE = ROOT / "data/snapshots/2026-10-24T014455Z/native-DNS-hardening-v11"


class DNSHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(SOURCE, self.bundle)
        self.data = json.loads((self.bundle / "observations.json").read_text())

    def tearDown(self):
        self.temp.cleanup()

    def final_policy(self):
        return [r for r in self.data["records"] if r["command"] ==
                ["docker", "exec", "ND_BLACK", "iptables-save", "-c"]][-1]

    def save(self):
        (self.bundle / "observations.json").write_text(json.dumps(self.data))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        for row in manifest["files"]:
            row["sha256"] = hashlib.sha256((self.bundle / row["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_complete_case(self):
        self.assertEqual(len(parse(self.bundle)["devices"]), 14)

    def test_earlier_allow_rejected(self):
        row = self.final_policy()
        row["stdout"] = row["stdout"].replace("[0:0] -A OUTPUT", "[0:0] -A OUTPUT -j ACCEPT\n[0:0] -A OUTPUT", 1)
        self.save()
        with self.assertRaisesRegex(ValueError, "prefix"):
            parse(self.bundle)

    def test_narrowed_deny_rejected(self):
        row = self.final_policy()
        row["stdout"] = row["stdout"].replace("-A OUTPUT -p tcp", "-A OUTPUT -d 1.1.1.1 -p tcp")
        self.save()
        with self.assertRaisesRegex(ValueError, "prefix"):
            parse(self.bundle)

    def test_missing_udp_rejected(self):
        row = self.final_policy()
        row["stdout"] = "\n".join(line for line in row["stdout"].splitlines()
                                   if "-A OUTPUT -p udp" not in line)
        self.save()
        with self.assertRaisesRegex(ValueError, "Missing DNS"):
            parse(self.bundle)

    def test_later_allow_is_permitted(self):
        row = self.final_policy()
        row["stdout"] = row["stdout"].replace("COMMIT", "[0:0] -A OUTPUT -j ACCEPT\nCOMMIT")
        self.save()
        self.assertEqual(len(parse(self.bundle)["devices"]), 14)

    def test_omitted_device_rejected(self):
        self.data["records"] = [r for r in self.data["records"]
                                if r["command"][:3] != ["docker", "exec", "ND_G_A1"]]
        self.save()
        with self.assertRaisesRegex(ValueError, "inventory"):
            parse(self.bundle)

    def test_changed_action_rejected(self):
        row = self.final_policy()
        row["stdout"] = row["stdout"].replace("-j REJECT", "-j ACCEPT")
        self.save()
        with self.assertRaisesRegex(ValueError, "action"):
            parse(self.bundle)


if __name__ == "__main__":
    unittest.main()
