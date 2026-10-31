"""Mutate only copied public IKE context records and verify strict correspondence."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_ike_contexts import parse, parse_listing
from validate_evidence import EvidenceError

BUNDLE = ROOT / "data/snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1"


class IKEContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(BUNDLE, self.bundle)
        self.snapshot = json.loads((self.bundle / "snapshot.json").read_text())

    def tearDown(self):
        self.temp.cleanup()

    def observation(self, device, suffix):
        return next(o for o in self.snapshot["observations"] if o["device_id"] == device and
                    o["command"][-len(suffix):] == suffix)

    def write(self):
        (self.bundle / "snapshot.json").write_text(json.dumps(self.snapshot))
        path = self.bundle / "manifest.json"
        manifest = json.loads(path.read_text())
        for row in manifest["files"]:
            file = self.bundle / row["path"]
            row["sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
            row["bytes"] = file.stat().st_size
        path.write_text(json.dumps(manifest))

    def raw_change(self, observation, update):
        path = self.bundle / observation["raw_path"]
        data = json.loads(path.read_text())
        data["stdout"] = update(data["stdout"])
        path.write_text(json.dumps(data))
        observation["raw_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write()

    def test_complete_contexts(self):
        result = parse(self.bundle)
        self.assertEqual(result["gateway_count"], 10)
        self.assertEqual(len({row["device"] for row in result["endpoints"]}), 10)
        self.assertEqual(sum(row["child_pfs"] is None for row in result["endpoints"]), 2)

    def test_failed_listing(self):
        self.observation("NF_I_A1", ["swanctl", "--list-sas"])["returncode"] = 1
        self.write()
        with self.assertRaises(EvidenceError):
            parse(self.bundle)

    def test_empty_error_is_failure(self):
        self.observation("NF_I_A1", ["swanctl", "--list-sas"])["error"] = ""
        self.write()
        with self.assertRaisesRegex(EvidenceError, "Failed"):
            parse(self.bundle)

    def test_wrong_device_command(self):
        self.observation("NF_I_A1", ["swanctl", "--list-sas"])["command"][2] = "NF_I_A2"
        self.write()
        with self.assertRaises(EvidenceError):
            parse(self.bundle)

    def test_child_spi_mismatch(self):
        observation = self.observation("NF_I_A1", ["swanctl", "--list-sas"])
        self.raw_change(observation, lambda text: text.replace("out cc0a8cda", "out cc0a8cdb"))
        with self.assertRaisesRegex(EvidenceError, "installed SAD"):
            parse(self.bundle)

    def test_ike_peer_epoch_mismatch(self):
        observation = self.observation("NF_I_B1", ["swanctl", "--list-sas"])
        self.raw_change(observation, lambda text: text.replace("45a4c3b9e629b660_i", "45a4c3b9e629b661_i"))
        with self.assertRaisesRegex(EvidenceError, "Reciprocal context"):
            parse(self.bundle)

    def test_identity_mismatch(self):
        observation = self.observation("NF_I_A1", ["swanctl", "--list-sas"])
        self.raw_change(observation, lambda text: text.replace("NF_I_B1.msc.test", "NF_I_B2.msc.test"))
        with self.assertRaisesRegex(EvidenceError, "identity/address"):
            parse(self.bundle)

    def test_extra_child_inventory(self):
        observation = self.observation("NF_I_A1", ["swanctl", "--list-sas"])
        self.raw_change(observation, lambda text: text + "  another CHILD\n")
        with self.assertRaisesRegex(EvidenceError, "Complete single"):
            parse(self.bundle)

    def test_selector_mismatch(self):
        observation = self.observation("NF_I_A1", ["swanctl", "--list-sas"])
        self.raw_change(observation, lambda text: text.replace("10.1.1.0/24", "10.1.2.0/24"))
        with self.assertRaisesRegex(EvidenceError, "selectors/reqid"):
            parse(self.bundle)

    def test_distinct_daemon_ids_are_permitted(self):
        observation = self.observation("NF_I_A1", ["swanctl", "--list-sas"])
        self.raw_change(observation, lambda text: text.replace("#51", "#999").replace("#278", "#888"))
        result = parse(self.bundle)
        self.assertEqual(result["endpoints"][0]["daemon_ike_id"], 999)

    def test_same_initiator_role_rejected(self):
        observation = self.observation("NF_I_B1", ["swanctl", "--list-sas"])
        self.raw_change(observation, lambda text: text.replace("_i* ", "_i ").replace("_r\n", "_r*\n"))
        with self.assertRaisesRegex(EvidenceError, "initiator roles"):
            parse(self.bundle)

    def test_peer_pfs_mismatch_rejected(self):
        observation = self.observation("NF_I_B1", ["swanctl", "--list-sas"])
        self.raw_change(observation, lambda text: text.replace("ESP:AES_GCM_16-256/ECP_384", "ESP:AES_GCM_16-256"))
        with self.assertRaisesRegex(EvidenceError, "CHILD PFS"):
            parse(self.bundle)

    def test_missing_listing(self):
        observation = self.observation("NF_I_A1", ["swanctl", "--list-sas"])
        self.snapshot["observations"].remove(observation)
        self.write()
        with self.assertRaises(EvidenceError):
            parse(self.bundle)


if __name__ == "__main__":
    unittest.main()
