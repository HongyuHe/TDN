import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_pf_dns import parse

SOURCE = ROOT / "artifacts/snapshots/2026-10-24T014455Z/freebsd-PF-complete-v12"


class PFDNSImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(SOURCE, self.bundle)
        self.data = json.loads((self.bundle / "observations.json").read_text())

    def tearDown(self):
        self.temp.cleanup()

    def reject(self, change):
        change(self.data["records"])
        (self.bundle / "observations.json").write_text(json.dumps(self.data))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        for row in manifest["files"]:
            row["sha256"] = hashlib.sha256((self.bundle / row["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            parse(self.bundle)

    def use_v13(self):
        shutil.rmtree(self.bundle)
        shutil.copytree(SOURCE.with_name("freebsd-PF-skip-v13"), self.bundle)
        self.data = json.loads((self.bundle / "observations.json").read_text())

    def test_real_enabled_interfaces(self):
        self.use_v13()
        self.assertTrue(parse(self.bundle)["hook_applicability_checked"])

    def test_skip_flag(self):
        self.use_v13()
        self.reject(lambda rs: rs[4].update(stdout=rs[4]["stdout"].replace("lo0\n", "lo0 (skip)\n")))

    def test_omitted_effective_interface(self):
        self.use_v13()
        self.reject(lambda rs: rs[4].update(stdout=rs[4]["stdout"].replace("lo0\n", "")))

    def test_real_complete_capture(self):
        result = parse(self.bundle)
        self.assertEqual([len(g["guards"]) for g in result["guests"]], [22, 22])

    def test_nonempty_initial_state(self):
        self.reject(lambda rs: rs[7].update(stdout="all tcp 1.2.3.4:53 -> 5.6.7.8:1000\n"))

    def test_translation(self):
        self.reject(lambda rs: rs[10].update(stdout="nat on vtnet0 from any to any -> 10.0.2.15\n"))

    def test_scrub_normalization(self):
        self.reject(lambda rs: rs[9].update(stdout="@0 scrub all reassemble tcp\n" + rs[9]["stdout"]))

    def test_added_local_address(self):
        self.reject(lambda rs: rs[3].update(stdout=rs[3]["stdout"] + "\tinet 192.0.2.77 netmask 0xffffffff\n"))

    def test_missing_rule(self):
        self.reject(lambda rs: rs[9].update(stdout=rs[9]["stdout"].replace(
            "@21 block return out quick inet proto udp from 10.100.1.2 to any port = domain",
            "")))

    def test_nonquick_rule(self):
        self.reject(lambda rs: rs[9].update(stdout=rs[9]["stdout"].replace("out quick", "out")))

    def test_rule_changes(self):
        self.reject(lambda rs: rs[38].update(stdout=rs[38]["stdout"].replace("10.100.1.2", "10.100.1.3")))

    def test_interface_scope_changes(self):
        self.reject(lambda rs: rs[9].update(stdout=rs[9]["stdout"].replace("on vtnet0", "on vtnet1")))

    def test_disabled_backend(self):
        self.reject(lambda rs: rs[6].update(stdout=rs[6]["stdout"].replace("Status: Enabled", "Status: Disabled")))

    def test_hidden_anchor(self):
        self.reject(lambda rs: rs[11].update(stdout="extra-anchor\n"))


if __name__ == "__main__":
    unittest.main()
