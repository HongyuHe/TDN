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
from import_family_execution import load_bundle, main

SOURCE = ROOT / "data/snapshots/2026-10-24T014455Z/families-v9/families-666"


class FamilyExecutionImportTests(unittest.TestCase):
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

    def mutate_bound_observation(self, kind, device, transform):
        commands = self.load("commands.json")
        indexed = {row["id"]: row for row in commands}
        for filename in ["stable-before.json", "stable-after.json"]:
            phase = self.load(filename)
            item = phase[device][kind]
            item["value"] = transform(item["value"])
            indexed[item["observation_id"]]["stdout"] = item["value"]
            self.save(filename, phase)
        self.save("commands.json", commands)

    def test_real_ipv6_bundle(self):
        self.run_import()

    def test_omitted_raw_rule_is_rejected(self):
        phase = self.load("stable-before.json")
        phase["IA"]["filters6"]["value"] = ""
        self.save("stable-before.json", phase)
        with self.assertRaisesRegex(ValueError, "differs from raw"):
            load_bundle(self.bundle)

    def test_broadened_export_is_rejected(self):
        phase = self.load("stable-before.json")
        phase["IA"]["filters6"]["value"] = phase["IA"]["filters6"]["value"].replace("--reqid 100", "--reqid 101")
        self.save("stable-before.json", phase)
        with self.assertRaisesRegex(ValueError, "differs from raw"):
            load_bundle(self.bundle)

    def test_extra_raw_rule_is_rejected(self):
        commands = self.load("commands.json")
        phase = self.load("stable-before.json")
        raw = next(row for row in commands if row["id"] == phase["IA"]["filters6"]["observation_id"])
        raw["stdout"] += "-A FORWARD -j ACCEPT\n"
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "differs from raw"):
            load_bundle(self.bundle)

    def test_missing_routing_inventory_is_rejected(self):
        phase = self.load("stable-before.json")
        del phase["IA"]["rules6"]
        self.save("stable-before.json", phase)
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            load_bundle(self.bundle)

    def test_wrong_command_with_consistent_export_is_rejected(self):
        commands = self.load("commands.json")
        phase = self.load("stable-before.json")
        raw = next(row for row in commands if row["id"] == phase["IA"]["rules6"]["observation_id"])
        raw["command"][-1] = "list"
        self.save("commands.json", commands)
        with self.assertRaisesRegex(ValueError, "Wrong raw command"):
            load_bundle(self.bundle)

    def test_peer_namespace_substitution_is_rejected(self):
        def swap(text):
            rows = json.loads(text)
            for row in rows:
                if row.get("name", "").endswith("-HA"):
                    row["name"] = row["name"][:-2] + "HB"
            return json.dumps(rows)
        self.mutate_bound_observation("peer_nsids", "IA", swap)
        with self.assertRaisesRegex(ValueError, "peer namespace"):
            self.run_import()

    def test_active_unmodeled_interface_is_rejected(self):
        def activate(text):
            rows = json.loads(text)
            next(row for row in rows if row["ifname"] == "gre0")["flags"].append("UP")
            return json.dumps(rows)
        self.mutate_bound_observation("interfaces", "IA", activate)
        with self.assertRaisesRegex(ValueError, "Active unsupported"):
            self.run_import()

    def test_wrong_immediate_header_offset_rejected(self):
        self.mutate_bound_observation("filters6", "IA", lambda text: text.replace("0x4>>0x8", "0x0>>0x8"))
        with self.assertRaisesRegex(ValueError, "not immediate Next Header"):
            self.run_import()

    def test_missing_terminal_raw_drop_rejected(self):
        self.mutate_bound_observation("filters6", "IA",
                                      lambda text: text.replace("-A EVA6_IMMEDIATE -j DROP\n", ""))
        with self.assertRaisesRegex(ValueError, "terminal immediate-header drop"):
            self.run_import()

    def mutate_early_gate(self, transform, bind=True):
        policy = self.load("early-header-policy.json")
        record = policy["rules"]["IA"]
        transform(record["ruleset"]["nftables"])
        if bind:
            commands = self.load("commands.json")
            next(r for r in commands if r["id"] == record["observation_id"])["stdout"] = json.dumps(record["ruleset"])
            self.save("commands.json", commands)
        self.save("early-header-policy.json", policy)

    def test_post_defrag_priority_rejected(self):
        self.mutate_early_gate(lambda rows: rows[2]["chain"].update(prio=-300))
        with self.assertRaisesRegex(ValueError, "priority"):
            self.run_import()

    def test_upper_protocol_substitution_rejected(self):
        def replace(rows):
            rows[4]["rule"]["expr"][0]["match"]["left"] = {"meta": {"key": "l4proto"}}
        self.mutate_early_gate(replace)
        with self.assertRaisesRegex(ValueError, "immediate IPv6"):
            self.run_import()

    def test_missing_early_drop_rejected(self):
        self.mutate_early_gate(lambda rows: rows[4]["rule"]["expr"].pop())
        with self.assertRaisesRegex(ValueError, "match/counter/drop"):
            self.run_import()

    def test_unbound_early_rule_rejected(self):
        self.mutate_early_gate(lambda rows: rows[2]["chain"].update(prio=-300), bind=False)
        with self.assertRaisesRegex(ValueError, "differs from complete raw"):
            self.run_import()

    def test_omitted_early_gateway_rejected(self):
        policy = self.load("early-header-policy.json")
        del policy["rules"]["IA"]
        self.save("early-header-policy.json", policy)
        with self.assertRaisesRegex(ValueError, "early-gate device inventory"):
            self.run_import()

    def test_missing_manifest_input_is_rejected(self):
        manifest = self.load("manifest.json")
        manifest["files"] = [row for row in manifest["files"] if row["path"] != "stable-before.json"]
        self.save("manifest.json", manifest)
        with self.assertRaisesRegex(ValueError, "Manifest omits"):
            load_bundle(self.bundle)


if __name__ == "__main__":
    unittest.main()
