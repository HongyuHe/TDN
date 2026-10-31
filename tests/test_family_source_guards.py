"""Test raw correspondence and semantic rejection for retained v13 source guards."""
import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_family_execution import main
from nft_source_policy import parse_table

SOURCE = ROOT / "data/snapshots/2026-10-24T014455Z/families-v13/families-444"


class FamilySourceGuardTests(unittest.TestCase):
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
        for item in manifest["files"]:
            item["sha256"] = hashlib.sha256((self.bundle / item["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def run_import(self):
        argv = ["import_family_execution.py", str(self.bundle), "--namespace", "Mutation",
                "--output", str(Path(self.temp.name) / "out.lean"),
                "--report", str(Path(self.temp.name) / "out.json")]
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            main()

    def test_actual_v13_import(self):
        self.run_import()
        report = json.loads((Path(self.temp.name) / "out.json").read_text())
        self.assertEqual(set(report["early_source_guards"]), {"IA", "IB", "OA", "OB"})

    def test_empty_error_string_is_failure(self):
        manifest = self.load("manifest.json")
        manifest["error"] = ""
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "experiment failed"):
            self.run_import()

    def test_omitted_source_rule_is_rejected(self):
        scope = self.load("source-policy-scope.json")
        scope["rules"]["IA"]["ruleset"]["nftables"].pop()
        self.save("source-policy-scope.json", scope)
        with self.assertRaisesRegex(ValueError, "differs from raw"):
            self.run_import()

    def test_extra_stable_rule_is_rejected_even_with_raw_binding(self):
        phase = self.load("stable-before.json")
        commands = self.load("commands.json")
        record = phase["IA"]["nft"]
        rules = json.loads(record["value"])
        target = next(item for item in rules["nftables"]
                      if "rule" in item and item["rule"]["table"] == "EVA_SOURCE_V13")
        rules["nftables"].append(copy.deepcopy(target))
        record["value"] = json.dumps(rules)
        next(row for row in commands if row["id"] == record["observation_id"])["stdout"] = record["value"]
        self.save("stable-before.json", phase)
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "full ruleset differs"):
            self.run_import()

    def test_wrong_nft_command_rejected(self):
        commands = self.load("commands.json")
        phase = self.load("stable-before.json")
        row = next(row for row in commands if row["id"] == phase["IA"]["nft"]["observation_id"])
        row["command"][-1] = "tables"
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "Wrong raw command"):
            self.run_import()

    def test_priority_after_route_is_rejected(self):
        scope = self.load("source-policy-scope.json")
        objects = [item for item in scope["rules"]["IA"]["ruleset"]["nftables"] if "metainfo" not in item]
        objects[1]["chain"]["prio"] = 0
        with self.assertRaisesRegex(ValueError, "precede routing"):
            parse_table(objects)

    def test_wrong_ipsec_path_index_is_rejected(self):
        scope = self.load("source-policy-scope.json")
        objects = [item for item in scope["rules"]["IA"]["ruleset"]["nftables"] if "metainfo" not in item]
        changed = False
        for item in objects:
            for expr in item.get("rule", {}).get("expr", []):
                left = expr.get("match", {}).get("left", {})
                if "ipsec" in left:
                    left["ipsec"]["spnum"] = 1
                    changed = True
        self.assertTrue(changed)
        with self.assertRaisesRegex(ValueError, "Unsupported nft"):
            parse_table(objects)


if __name__ == "__main__":
    unittest.main()
