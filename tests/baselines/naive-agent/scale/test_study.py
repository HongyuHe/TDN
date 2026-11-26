import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from cohort import registered_profile
from scale.catalog import BY_NAME, CASES, CHANGES
from scale.level_policy import bindings, effective_topology
from scale.profiles import NETWORKS, inventory, profile


class ScalingDesign(unittest.TestCase):
    def test_counts_and_wiring(self):
        for name, levels, branches in (
            ("Base", 2, 1),
            ("10xLevels", 20, 1),
            ("10xDevices", 2, 10),
        ):
            with self.subTest(name=name):
                p = profile(name)
                self.assertTrue(registered_profile(p))
                spec = p["topology"]
                nodes = {d["id"]: d for d in spec["devices"]}
                self.assertEqual(len(nodes), inventory(name)["devices"])
                declared = {
                    (d["id"], i["name"])
                    for d in nodes.values()
                    for i in d["interfaces"]
                }
                ends = [
                    (e["device"], e["interface"])
                    for link in spec["links"]
                    for e in link.values()
                ]
                self.assertEqual(declared, set(ends))
                self.assertEqual(len(ends), len(declared))
                for site in ("A", "B"):
                    rows = [d for d in nodes.values() if d.get("site") == site]
                    self.assertEqual(
                        sum(d["role"] == "inner" for d in rows), levels * branches
                    )
                    self.assertEqual(
                        sum(d["role"] == "gray-firewall" for d in rows), branches
                    )
                    for role in ("transport", "outer", "firewall"):
                        self.assertEqual(sum(d["role"] == role for d in rows), branches)
                    self.assertEqual(
                        sum(
                            d["role"] == "switch" and d.get("level") != "management"
                            for d in rows
                        ),
                        levels * branches,
                    )
                for d in nodes.values():
                    if "tunnel" in d:
                        self.assertEqual(
                            nodes[d["tunnel"]["peer"]]["tunnel"]["peer"], d["id"]
                        )
                self.assertEqual(len(list(bindings(spec))), 2 * branches * levels)
        self.assertEqual([inventory(n)["devices"] for n in NETWORKS], [33, 213, 321])

    def test_scope_and_independent_designations(self):
        self.assertEqual(set(BY_NAME), set(CHANGES))
        self.assertEqual(len(CASES), len(BY_NAME))
        self.assertEqual(len(CASES), 20)
        targets = {"007", "008", "013", "029", "030", "034", "035", "038", "039", "040"}
        import re

        self.assertEqual(
            {g for c in CASES for g in re.findall(r"RG-(\d{3})", c.clause)}, targets
        )
        spec = profile("Base")["topology"]
        rows = list(bindings(spec))
        red, inner, aw, old = next(r for r in rows if r[0].endswith("_R_B1"))
        active = effective_topology(
            spec,
            [{"red": red, "attached_inner": inner, "record": {"security_level": "S2"}}],
        )
        self.assertEqual(
            next(d["level"] for d in spec["devices"] if d["id"] == red), old
        )
        self.assertEqual(
            {d["level"] for d in active["devices"] if d["id"] in (red, inner)}, {"S2"}
        )

    def test_detector_view_has_no_oracle(self):
        from snapshot_inputs import FORBIDDEN
        from blind_audit import PROMPT
        from run_snapshot_audits import TOOLS

        self.assertEqual(TOOLS, {"document", "networks", "observe"})
        for c in CASES:
            self.assertNotIn(c.key, PROMPT)
        self.assertFalse(FORBIDDEN.search(PROMPT.encode()))


class RecoveryTests(unittest.TestCase):
    def test_restore_reestablishes_a_peer_before_repeating_the_clean_probe(self):
        from tempfile import TemporaryDirectory
        from unittest.mock import patch
        from scale.live import held

        events = []

        def change(action, token):
            events.append(action)
            return {"applied": action}

        def check(token):
            events.append("observe")
            return {"observed": events.count("observe") == 2}

        def restore(p):
            events.append("bring up original tunnel")
            return {"ready": True}

        with (
            TemporaryDirectory() as tmp,
            patch("scale.live.change_and_read", return_value=(change, check)),
            patch("restore_health.verify", side_effect=restore),
        ):
            with held(
                profile("Base"), "inner-peer-loopback", Path(tmp) / "trial"
            ) as result:
                self.assertTrue(result["observed"])
        self.assertEqual(
            events,
            [
                "observe",
                "edit",
                "observe",
                "restore",
                "bring up original tunnel",
                "observe",
            ],
        )

    def test_only_service_failures_before_any_reader_access_are_retried(self):
        from tempfile import TemporaryDirectory
        from scale.study import service_busy

        with TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "events.jsonl").write_text(
                '{"type":"error","message":"429 Too Many Requests"}\n'
            )
            for calls, status, expected in [
                (0, "invalid_run", True),
                (2, "invalid_run", False),
                (0, "timeout", False),
            ]:
                (p / "execution.json").write_text(
                    json.dumps({"status": status, "reader_calls": calls})
                )
                self.assertEqual(service_busy(p), expected)
