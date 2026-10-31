import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/construction"))
from raw_correspondence import check_filter_correspondence, parse_iptables_save, raw_interface_addresses
from validate_evidence import EvidenceError


class RawCorrespondenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.raw = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n-A FORWARD -s 10.0.0.1/32 -j ACCEPT\nCOMMIT\n"
        self.write_raw(self.raw)
        parsed = parse_iptables_save(self.raw)
        self.snapshot = {"observations": [{"id": "obs", "device_id": "D", "kind": "filters4", "returncode": 0, "raw_path": "raw.json"}], "filters": []}
        for name, data in parsed.items():
            rules = [{"ordinal": n, "matches": {"iptables_tokens": r["tokens"]}, "action": r["action"], "raw_text": r["raw"]} for n, r in enumerate(data["rules"])]
            self.snapshot["filters"].append({"id": "D:" + name, "device_id": "D", "family": 4, "table": "filter", "chain": name, "policy": data["policy"], "ordered_rules": rules, "observation_ids": ["obs"]})

    def tearDown(self):
        self.temporary.cleanup()

    def write_raw(self, value):
        (self.root / "raw.json").write_text(json.dumps({"stdout": value, "stderr": ""}))

    def forward(self):
        return next(c for c in self.snapshot["filters"] if c["chain"] == "FORWARD")

    def test_exact_round_trip(self):
        self.assertEqual(check_filter_correspondence(self.root, self.snapshot)["chains"], 3)

    def test_omitted_normalized_allow_is_rejected(self):
        self.forward()["ordered_rules"] = []
        with self.assertRaises(EvidenceError):
            check_filter_correspondence(self.root, self.snapshot)

    def test_broadened_normalized_match_is_rejected(self):
        self.forward()["ordered_rules"][0]["matches"]["iptables_tokens"] = ["-s", "10.0.0.0/24"]
        with self.assertRaises(EvidenceError):
            check_filter_correspondence(self.root, self.snapshot)

    def test_extra_raw_allow_is_rejected(self):
        self.write_raw(self.raw.replace("COMMIT", "-A FORWARD -j ACCEPT\nCOMMIT"))
        with self.assertRaises(EvidenceError):
            check_filter_correspondence(self.root, self.snapshot)

    def test_changed_default_is_rejected(self):
        self.forward()["policy"] = "accept"
        with self.assertRaises(EvidenceError):
            check_filter_correspondence(self.root, self.snapshot)

    def test_omitted_chain_is_rejected(self):
        self.snapshot["filters"] = [c for c in self.snapshot["filters"] if c["chain"] != "OUTPUT"]
        with self.assertRaises(EvidenceError):
            check_filter_correspondence(self.root, self.snapshot)

    def test_omitted_entire_table_is_rejected(self):
        self.snapshot["filters"] = []
        with self.assertRaises(EvidenceError):
            check_filter_correspondence(self.root, self.snapshot)

    def test_actual_interface_address_binding(self):
        addresses = [{"family": "inet", "local": "10.100.1.2", "prefixlen": 24}]
        self.write_raw(json.dumps([{"ifname": "gray", "addr_info": addresses}]))
        self.snapshot["interfaces"] = [{"device_id": "D", "name": "gray", "addresses": addresses, "observation_ids": ["obs"]}]
        self.assertEqual(raw_interface_addresses(self.root, self.snapshot, "D", "gray"), {"10.100.1.2"})
        self.snapshot["interfaces"][0]["addresses"] = [{"family": "inet", "local": "10.100.2.2", "prefixlen": 24}]
        with self.assertRaises(EvidenceError):
            raw_interface_addresses(self.root, self.snapshot, "D", "gray")


if __name__ == "__main__":
    unittest.main()
