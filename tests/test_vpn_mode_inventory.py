"""Check complete VPN policy coverage and exact-file/runtime correspondence."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_vpn_modes import parse
from loaded_policy import proposal_modes

BASE = ROOT / "artifacts/snapshots/2026-10-24T014455Z/native-baseline-20261024T015000Z"
SHARED = ROOT / "artifacts/snapshots/2026-10-24T014455Z/native-shared-four-levels-20261024T015300Z-coverage-v1"


class VPNModeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(BASE, self.bundle)

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self):
        return json.loads((self.bundle / "snapshot.json").read_text())

    def save(self, relative, value):
        (self.bundle / relative).write_text(json.dumps(value))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        for row in manifest["files"]:
            if row["path"] == relative:
                row["sha256"] = hashlib.sha256((self.bundle / relative).read_bytes()).hexdigest()
                row["bytes"] = (self.bundle / relative).stat().st_size
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_complete_baseline(self):
        result = parse(self.bundle)
        self.assertEqual(len(result["bindings"]), 8)

    def test_complete_shared_uses_same_importer(self):
        self.assertEqual(len(parse(SHARED)["bindings"]), 10)

    def test_omitted_gateway_policy_rejected(self):
        snapshot = self.snapshot()
        snapshot["tunnels"].pop()
        self.save("snapshot.json", snapshot)
        with self.assertRaises(ValueError):
            parse(self.bundle)

    def test_changed_loaded_configuration_rejected(self):
        snapshot = self.snapshot()
        snapshot["tunnels"][0]["loaded_public_configuration"] = snapshot["tunnels"][0]["loaded_public_configuration"].replace("version = 2", "version = 1")
        self.save("snapshot.json", snapshot)
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            parse(self.bundle)

    def test_omitted_runtime_connection_rejected(self):
        snapshot = self.snapshot()
        snapshot["tunnels"][0]["all_runtime_connections"] = ""
        self.save("snapshot.json", snapshot)
        with self.assertRaises(ValueError):
            parse(self.bundle)

    def test_failed_exact_file_load_rejected(self):
        snapshot = self.snapshot()
        snapshot["tunnels"][0]["load_confirmation"]["returncode"] = 1
        self.save("snapshot.json", snapshot)
        with self.assertRaisesRegex(ValueError, "confirmation"):
            parse(self.bundle)

    def test_cbc_without_integrity_rejected(self):
        with self.assertRaisesRegex(ValueError, "HMAC"):
            proposal_modes("aes256-ecp384", True)

    def test_implicit_default_proposals_rejected(self):
        with self.assertRaisesRegex(ValueError, "default"):
            proposal_modes("default", False)

    def mutate_observation(self, kind, field, value, configured=False):
        snapshot = self.snapshot()
        tunnel = snapshot["tunnels"][0]
        row = next(o for o in snapshot["observations"]
                   if o["id"] in tunnel["observation_ids"] and o["kind"] == kind)
        row[field] = value(row[field]) if callable(value) else value
        if configured:
            tunnel["status"] = "configured"
        self.save("snapshot.json", snapshot)

    def test_configured_tunnel_with_failed_read_rejected(self):
        self.mutate_observation("loaded-public-config", "returncode", 1, True)
        with self.assertRaisesRegex(ValueError, "observed gateway and tunnel"):
            parse(self.bundle)

    def test_configured_tunnel_with_failed_runtime_rejected(self):
        self.mutate_observation("connections-raw", "returncode", 1, True)
        with self.assertRaisesRegex(ValueError, "observed gateway and tunnel"):
            parse(self.bundle)

    def test_wrong_read_device_rejected(self):
        self.mutate_observation("loaded-public-config", "device_id", "NB_I_B1")
        with self.assertRaisesRegex(ValueError, "ordering or content"):
            parse(self.bundle)

    def test_wrong_runtime_device_rejected(self):
        self.mutate_observation("connections-raw", "device_id", "NB_I_B1")
        with self.assertRaisesRegex(ValueError, "ordering or content"):
            parse(self.bundle)

    def test_wrong_read_command_target_rejected(self):
        self.mutate_observation("loaded-public-config", "command",
                                lambda command: command[:2] + ["NB_I_B1"] + command[3:])
        with self.assertRaisesRegex(ValueError, "ordering or content"):
            parse(self.bundle)

    def test_wrong_runtime_command_target_rejected(self):
        self.mutate_observation("connections-raw", "command",
                                lambda command: command[:2] + ["NB_I_B1"] + command[3:])
        with self.assertRaisesRegex(ValueError, "ordering or content"):
            parse(self.bundle)

    def test_wrong_load_command_target_rejected(self):
        snapshot = self.snapshot()
        observation_id = snapshot["tunnels"][0]["load_confirmation"]["observation_id"]
        row = next(o for o in snapshot["observations"] if o["id"] == observation_id)
        row["command"][2] = "NB_I_B1"
        self.save("snapshot.json", snapshot)
        with self.assertRaisesRegex(ValueError, "load command target"):
            parse(self.bundle)

    def test_incomplete_device_inventory_rejected(self):
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        manifest["inventory_complete"]["devices"]["complete"] = False
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "complete device/tunnel"):
            parse(self.bundle)

    def test_incomplete_tunnel_inventory_rejected(self):
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        manifest["inventory_complete"]["tunnels"]["complete"] = False
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "complete device/tunnel"):
            parse(self.bundle)

    def test_unparsed_load_rejected(self):
        snapshot = self.snapshot()
        observation_id = snapshot["tunnels"][0]["load_confirmation"]["observation_id"]
        row = next(o for o in snapshot["observations"] if o["id"] == observation_id)
        row["parse_status"] = "unparsed"
        self.save("snapshot.json", snapshot)
        with self.assertRaisesRegex(ValueError, "confirmation"):
            parse(self.bundle)


if __name__ == "__main__":
    unittest.main()
