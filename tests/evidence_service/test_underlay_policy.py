"""Check declared underlay permissions without inferring intent from filter rules."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tdn_evidence.underlay_policy import parse, query_experiment, read_experiment_raw


class UnderlayPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = {"schema": "native-underlay-policy/v1", "authority": "emulation-owner",
            "source": {"kind": "user-instruction", "quote": "Use OSPF on the underlay."},
            "protocols": ["ospf"], "hooks": ["input", "output"],
            "multicastDestinations": ["224.0.0.5"], "peerScope": "directly-connected-black-peer",
            "profiles": {"sample": "profile-sample.json"}}
        self.profile = {"devices": [
            {"id": "edge", "role": "firewall", "interfaces": [
                {"name": "outside", "zone": "black", "address": "192.0.2.1/30"}]},
            {"id": "router", "role": "transport", "interfaces": [
                {"name": "eth7", "zone": "black", "address": "192.0.2.2/30"}]}],
            "links": [{"a": {"device": "edge", "interface": "outside"},
                       "b": {"device": "router", "interface": "eth7"}}]}
        self.write()

    def write(self):
        for name, value in [("policy.json", self.policy), ("profile-sample.json", self.profile)]:
            (self.root / name).write_text(json.dumps(value))
        files = [{"path": name, "sha256": hashlib.sha256((self.root / name).read_bytes()).hexdigest()}
                 for name in ["policy.json", "profile-sample.json"]]
        (self.root / "manifest.json").write_text(json.dumps({"files": files}))

    def test_permissions_bind_declared_links_and_directions(self):
        _, report = parse(self.root)
        self.assertEqual({(r["hook"], r["source"], r["destination"]) for r in report["approvals"]}, {
            ("input", "192.0.2.2", "192.0.2.1"), ("input", "192.0.2.2", "224.0.0.5"),
            ("output", "192.0.2.1", "192.0.2.2"), ("output", "192.0.2.1", "224.0.0.5")})
        self.assertTrue(all(r["evidenceStatus"] == "declared" for r in report["approvals"]))
        page = query_experiment(self.root, "example", "approvals", "edge", 0, 1)
        self.assertEqual((page["total"], page["next_offset"]), (4, 1))
        self.assertEqual(json.loads(read_experiment_raw(self.root, "policy")), self.policy)

    def test_forwarded_or_broader_protocol_approval_is_rejected(self):
        for key, value in [("hooks", ["input", "output", "forward"]),
                           ("protocols", ["ospf", "tcp"]),
                           ("multicastDestinations", ["224.0.0.6"])]:
            original = self.policy[key]
            self.policy[key] = value
            self.write()
            with self.subTest(key=key), self.assertRaises(ValueError):
                parse(self.root)
            self.policy[key] = original

    def test_wrong_peer_or_duplicate_link_is_rejected(self):
        self.profile["devices"][1]["role"] = "inner"
        self.write()
        with self.assertRaises(ValueError):
            parse(self.root)
        self.profile["devices"][1]["role"] = "transport"
        self.profile["links"].append(self.profile["links"][0])
        self.write()
        with self.assertRaises(ValueError):
            parse(self.root)

    def test_changed_source_bytes_are_rejected(self):
        with (self.root / "policy.json").open("a") as stream:
            stream.write(" ")
        with self.assertRaises(ValueError):
            parse(self.root)


if __name__ == "__main__":
    unittest.main()
