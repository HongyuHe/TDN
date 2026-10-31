import hashlib
import json
import re
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_pairing_execution import parse

SOURCE = ROOT / "data/snapshots/2026-10-24T014455Z/pairings-v5/layers-macsec-ipsec-integrated"


class PairingExecutionTests(unittest.TestCase):
    source = SOURCE
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(self.source, self.bundle)
        self.phase_file = "bridged-before.json" if (self.bundle / "bridged-before.json").exists() else "stable-before.json"
        self.before = json.loads((self.bundle / self.phase_file).read_text())
        self.commands = json.loads((self.bundle / "commands.json").read_text())

    def tearDown(self):
        self.temp.cleanup()

    def mutate(self, device, kind, transform, bind=True):
        row = self.before[device][kind]
        row["value"] = transform(row["value"])
        if bind:
            next(r for r in self.commands if r["id"] == row["observation_id"])["stdout"] = row["value"]
        (self.bundle / self.phase_file).write_text(json.dumps(self.before))
        (self.bundle / "commands.json").write_text(json.dumps(self.commands))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        for item in manifest["files"]:
            item["sha256"] = hashlib.sha256((self.bundle / item["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            parse(self.bundle)

    def test_all_six_current_inputs(self):
        for path in self.source.parent.iterdir():
            if path.is_dir():
                result = parse(path)
                self.assertTrue(result["operational"]["links"])

    def test_unbound_normalized_interface(self):
        self.mutate("IA", "interfaces", lambda s: s.replace('"encrypt":true', '"encrypt":false'), False)

    def test_weakened_protection(self):
        self.mutate("IA", "interfaces", lambda s: s.replace('"protect":true', '"protect":false'))

    def test_redirect(self):
        self.mutate("IA", "tc", lambda s: s.replace("\n[]\n[]\n", '\n[{"kind":"bpf"}]\n[]\n', 1))

    def test_missing_tc_interface(self):
        self.mutate("IA", "tc", lambda s: "\n".join(s.splitlines()[4:]) + "\n")

    def test_wrong_session(self):
        self.mutate("OA", "l2tp_sessions", lambda s: s.replace("Peer session 200", "Peer session 201"))

    def test_bridge_member_omission(self):
        self.mutate("OA", "bridge_links", lambda s: json.dumps(json.loads(s)[1:]))

    def test_wrong_peer_namespace(self):
        self.mutate("IA", "peer_nsids", lambda s: re.sub(r"([A-Za-z0-9]+)-HA", r"\1-HB", s))

    def test_unknown_nft_transform(self):
        self.mutate("IA", "nft_ruleset", lambda s: json.dumps({"nftables": [{"rule": {
            "expr": [{"mangle": {"key": "ip daddr", "value": "10.2.0.2"}}]}}]}))

    def test_optional_ipsec_template(self):
        self.mutate("OA", "policies", lambda s: s.replace("level required", "level use"))

    def test_changed_route(self):
        self.mutate("OA", "routes4", lambda s: s.replace('"gateway":"192.0.2.2"', '"gateway":"192.0.2.3"'))


class PairingV7Tests(PairingExecutionTests):
    source = ROOT / "data/snapshots/2026-10-24T014455Z/pairings-v7/layers-macsec-ipsec-integrated"


class BridgedV8Tests(PairingExecutionTests):
    source = ROOT / "data/snapshots/2026-10-24T014455Z/bridged-macsec-v8/bridged-Inner-MACsec-Outer-IPsec"

    def test_ethernet_only_inner_is_imported(self):
        result = parse(self.source)
        self.assertEqual(result["phase_files"], ["bridged-before.json", "bridged-after.json"])
        for key in ["HA:red", "HB:red", "IA:red", "IA:macsec0", "IB:red", "IB:macsec0"]:
            self.assertFalse(any(a[0] == "inet" for a in result["operational"]["interfaces"][key]["addresses"]))
        self.assertIn("IA:macsec0", result["address_epochs"])

    def test_omitted_inner_bridge_member(self):
        self.mutate("IA", "bridge_links", lambda s: json.dumps(json.loads(s)[1:]))

    def test_changed_linklocal_route_preference(self):
        self.mutate("IA", "routes6", lambda s: s.replace('"metric":256', '"metric":1', 1))


if __name__ == "__main__":
    unittest.main()
