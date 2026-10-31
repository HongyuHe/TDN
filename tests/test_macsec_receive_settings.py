"""Receive-side runtime settings must support the imported must-secure claim."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_macsec_protection import parse

BASE = ROOT / "artifacts/snapshots/2026-10-24T014455Z"


class MACsecReceiveSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.case = Path(self.temp.name) / "case"
        shutil.copytree(BASE / "eap-tls-forward-v18", self.case)

    def tearDown(self):
        self.temp.cleanup()

    def change_runtime(self, key, value, old_text, new_text):
        state = json.loads((self.case / "stable-after.json").read_text())
        raw = json.loads((self.case / "commands.json").read_text())
        commands = {row["id"]: row for row in raw}
        interfaces = state["P0"]["interfaces"]
        rows = json.loads(interfaces["value"])
        macsec = next(row for row in rows if row.get("linkinfo", {}).get("info_kind") == "macsec")
        macsec["linkinfo"]["info_data"][key] = value
        interfaces["value"] = json.dumps(rows)
        commands[interfaces["observation_id"]]["stdout"] = interfaces["value"]
        settings = state["P0"]["macsec"]
        settings["value"] = settings["value"].replace(old_text, new_text)
        commands[settings["observation_id"]]["stdout"] = settings["value"]
        manifest = json.loads((self.case / "manifest.json").read_text())
        for name, data in [("stable-after.json", state), ("commands.json", raw)]:
            path = self.case / name
            path.write_text(json.dumps(data))
            entry = next(row for row in manifest["files"] if row["path"] == name)
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.case / "manifest.json").write_text(json.dumps(manifest))

    def run_import(self):
        return parse([self.case], BASE / "hostap-kdf-bindings-v4", BASE / "final-hostap-runtime-v4",
                     BASE / "hostap-auth-lowest-pn-v5")

    def test_disabled_receive_validation_is_rejected(self):
        self.change_runtime("validation", "disabled", "validate strict", "validate disabled")
        with self.assertRaisesRegex(ValueError, "strict receive validation"):
            self.run_import()

    def test_disabled_replay_protection_is_rejected(self):
        self.change_runtime("replay_protect", False, "replay on", "replay off")
        with self.assertRaisesRegex(ValueError, "strict receive validation"):
            self.run_import()


    def test_check_mode_is_not_strict_validation(self):
        self.change_runtime("validation", "check", "validate strict", "validate check")
        with self.assertRaisesRegex(ValueError, "strict receive validation"):
            self.run_import()

    def test_json_text_disagreement_is_rejected(self):
        self.change_runtime("validation", "disabled", "validate strict", "validate strict")
        with self.assertRaisesRegex(ValueError, "observations differ"):
            self.run_import()

    def test_replay_enabled_requires_a_boolean(self):
        self.change_runtime("replay_protect", 1, "replay on", "replay on")
        with self.assertRaisesRegex(ValueError, "runtime settings differ"):
            self.run_import()


if __name__ == "__main__":
    unittest.main()
