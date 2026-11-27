import gzip
import hashlib
import json
from pathlib import Path
import random
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from observed_profile import capture_topology
from scale import blinding, panel
from scale.observation_window import fingerprint, freeze_then_confirm, validate_window
from scale.profiles import NETWORKS
from scale.review import identifies_device, record_findings
from scale.report import alert_statistics
from scale.service_policy import (
    ordered_regions,
    proof_input as service_input,
    reverse_sources,
)
from tdn_evidence.parsers.correspondence import parse_iptables_save


class StudyMethod(unittest.TestCase):
    def test_firewall_depth_starts_at_row_two(self):
        self.assertEqual([panel.rule_depth_third(i, 7) for i in range(2, 8)], [0, 0, 1, 1, 2, 2])
        self.assertEqual(panel.rule_depth_third(2, 2), 0)
        for length in (1, 2, 7, 500):
            with self.subTest(length=length), self.assertRaisesRegex(ValueError, "row 2 or later"):
                panel.rule_depth_third(1, length)

    def test_first_rule_check_covers_companion_chains_and_both_address_families(self):
        def chain(device, family, name, actions, obs):
            return {"device_id": device, "table": "filter", "family": family, "chain": name,
                    "ordered_rules": [{"ordinal":i, "raw_text":f"-A {name} -j {a.upper()}",
                                       "observation_ids":[obs]} for i,a in enumerate(actions)]}
        def rules(forward, other, input_actions, obs):
            return panel.first_filter_rules({"filters":[
                chain("g1",4,"FORWARD",forward,obs), chain("g1",4,"OUTPUT",other,obs),
                chain("g2",6,"INPUT",input_actions,obs)]})
        clean=rules(["drop","accept"],["drop"],[],"previous")
        allowed=rules(["drop","drop"],["drop"],[],"later")
        self.assertEqual(panel.changed_first_rules(clean,allowed),[])
        other_chain=rules(["drop","drop"],["accept","drop"],["drop"],"later")
        self.assertEqual(panel.changed_first_rules(clean,other_chain),[("g1",4,"OUTPUT"),("g2",6,"INPUT")])
        removed=rules(["accept"],[],[],"later")
        self.assertEqual(panel.changed_first_rules(clean,removed),[("g1",4,"FORWARD"),("g1",4,"OUTPUT")])

    def test_old_seal_and_known_first_row_fixture_cannot_start_a_new_run(self):
        from scale.live import held
        with TemporaryDirectory() as tmp:
            folder=Path(tmp)
            (folder/"approved-panel.json").write_text('{"inputs":{}}')
            with self.assertRaisesRegex(ValueError, "predates"):
                panel.approved_panel(folder)
            for key in ("gray-ordinary-http", "shared-inner-gateway"):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "row 1"), held({},key,folder/key):
                    self.fail("An archived first-row fixture was allowed to apply a change")
                self.assertFalse((folder/key).exists())

    def test_alert_can_identify_a_unique_address_or_describe_a_device(self):
        with TemporaryDirectory() as tmp:
            folder=Path(tmp); (folder/"native").mkdir()
            data=dict(devices=[dict(id="r1",role="outer",site="A"),dict(id="r10",role="inner",site="A")],
                      interfaces=[dict(device_id="r1",addresses=[dict(local="10.0.0.1"),dict(local="127.0.0.1")]),
                                  dict(device_id="r10",addresses=[dict(local="127.0.0.1")])])
            (folder/"native/snapshot.json").write_text(json.dumps(data))
            self.assertTrue(identifies_device("10.0.0.1 admits the service.", "r1", folder, {}))
            self.assertFalse(identifies_device("r10 sees 127.0.0.1.", "r1", folder, {}))
            note="The only Outer gateway at Site A admits the service."
            self.assertTrue(identifies_device(note,"r1",folder,{"location_quotation":note,
                            "device_description":{"role":"outer","site":"A"}}))

    def test_panel_seals_matching_observations_and_refuses_an_unobserved_placement(
        self,
    ):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            kind = next(c for c in panel.CASES if c.key == "inner-mode")
            anchor = "XB_I_A1"
            for healthy in (True, False):
                folder = root / ("control" if healthy else "trial/capture")
                oracle = root / (
                    "healthy.json" if healthy else "trial/operator/held.json"
                )

                def collect():
                    folder.mkdir(parents=True)
                    (folder / "capture.json").write_text('{"converged":true}')
                    for name in (
                        "native/manifest.json",
                        "processing/observations.json",
                        "native/snapshot.json",
                    ):
                        f = folder / "snapshot" / name
                        f.parent.mkdir(parents=True, exist_ok=True)
                        f.write_text('{"links":[],"tunnels":[],"interfaces":[],"filters":[]}')

                def confirm():
                    oracle.parent.mkdir(parents=True, exist_ok=True)
                    oracle.write_text(json.dumps({"device": anchor, "observed": True}))
                    return oracle

                freeze_then_confirm(folder, panel.BACKGROUND_PLAN, collect, confirm)
            (root / "trial/cell.json").write_text(
                json.dumps(dict(network="Base", case=kind.key, observed=True))
            )
            (root / "trial/post-health.json").write_text('{"ready":true}')
            donor = dict(
                network="Base",
                case=kind.key,
                anchor=anchor,
                level="S1",
                trial="trial",
                location_evidence="operator/held.json",
                location_sha256=fingerprint(root / "trial/operator/held.json"),
            )
            path = root / "donors.json"
            path.write_text(
                json.dumps(dict(controls={"Base": "control"}, trials=[donor]))
            )
            with (
                patch.object(panel, "NETWORKS", ["Base"]),
                patch.object(panel, "CASES", [kind]),
                patch.object(panel, "cases_for", return_value=[kind]),
                patch.object(
                    panel, "detector_input", return_value=("original", "reader")
                ),
            ):
                for location, matches in ((anchor, True), ("XB_I_B2", False)):
                    study = root / location
                    study.mkdir()
                    plan = {
                        "seed": "10" * 32,
                        "cells": {
                            "Base/inner-mode": {
                                "anchor": location,
                                "level": "S1",
                                "rule_depth_third": None,
                            }
                        },
                    }
                    (study / "placement-plan.json").write_text(json.dumps(plan))
                    (study / "protocol.json").write_text(
                        json.dumps(
                            {
                                "method_version": 2,
                                "placement_sha256": fingerprint(
                                    study / "placement-plan.json"
                                )
                            }
                        )
                    )
                    if matches:
                        panel.prepare(study, path)
                        sealed = json.loads(
                            (study / "approved-panel.json").read_bytes()
                        )
                        self.assertEqual(panel.approved_panel(study)["minimum_changed_rule_position"], 2)
                        self.assertEqual(
                            set(sealed["inputs"]),
                            {"Base/inner-mode", "Base/healthy-control"},
                        )
                    else:
                        with self.assertRaisesRegex(
                            ValueError, "outstanding panel checks"
                        ):
                            panel.prepare(study, path)
                        self.assertFalse((study / "approved-panel.json").exists())
                reject = root / "companion-chain"
                reject.mkdir()
                for filename in ("placement-plan.json", "protocol.json"):
                    (reject / filename).write_bytes((root / anchor / filename).read_bytes())
                snapshot = root / "trial/capture/snapshot/native/snapshot.json"
                captured = json.loads(snapshot.read_bytes())
                captured["filters"] = [{"device_id":"g2","family":6,"chain":"OUTPUT","table":"filter",
                                        "ordered_rules":[{"ordinal":0,"raw_text":"-A OUTPUT -j ACCEPT"}]}]
                snapshot.write_text(json.dumps(captured))
                with self.assertRaisesRegex(ValueError, "outstanding panel checks"):
                    panel.prepare(reject, path)
                audit = json.loads((reject/"panel-preflight.json").read_bytes())
                self.assertIn("Firewall rule 1 differs from the healthy control in g2 IPv6 OUTPUT", audit["errors"][0])
                self.assertFalse((reject / "approved-panel.json").exists())

    def test_an_active_confirmation_must_follow_the_frozen_capture(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "capture"
            plan = root / "shared-traffic.json"
            plan.write_text('{"workload":"ordinary"}')

            def collect():
                for name in ("native/manifest.json", "processing/observations.json"):
                    source = capture / "snapshot" / name
                    source.parent.mkdir(parents=True)
                    source.write_text("{}")

            def confirm():
                self.assertTrue((capture / "observation-seal.json").exists())
                receipt = root / "operator.json"
                receipt.write_text('{"observed":true}')
                return receipt

            freeze_then_confirm(capture, plan, collect, confirm)
            digest = fingerprint(root / "operator.json")
            validate_window(capture, fingerprint(plan), digest)
            with self.assertRaisesRegex(ValueError, "different observation"):
                validate_window(capture, fingerprint(plan), "0" * 64)
            record = capture / "confirmation.json"
            data = json.loads(record.read_bytes())
            data["began_ns"] = 0
            record.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "overlapped"):
                validate_window(capture, fingerprint(plan), digest)

    def test_reader_rewrites_collector_references_without_rewriting_real_names(self):
        views = {
            "raw": [
                {"record": {"id": "obs-00004", "stdout": "real interface link-400"}}
            ],
            "links": [{"record": {"id": "link-400", "observation_ids": ["obs-00004"]}}],
            "filters": [
                {"record": {"ordered_rules": [{"observation_ids": ["obs-00004"]}]}}
            ],
        }
        blinding.anonymize_collector_ids(views, b"study")
        obs = views["raw"][0]["record"]["id"]
        self.assertNotEqual(obs, "obs-00004")
        self.assertNotEqual(views["links"][0]["record"]["id"], "link-400")
        self.assertEqual(views["links"][0]["record"]["observation_ids"], [obs])
        self.assertEqual(
            views["filters"][0]["record"]["ordered_rules"][0]["observation_ids"], [obs]
        )
        self.assertEqual(views["raw"][0]["record"]["stdout"], "real interface link-400")

    def test_http_authorization_uses_independent_endpoints_and_port_in_both_directions(
        self,
    ):
        devices = [
            {
                "id": "gw1",
                "role": "inner",
                "interfaces": [],
                "level": "S1",
                "tunnel": {"peer": "gw2", "local": "10.0.0.1"},
            },
            {
                "id": "gw2",
                "role": "inner",
                "interfaces": [],
                "level": "S1",
                "tunnel": {"peer": "gw1", "local": "10.1.0.1"},
            },
            {
                "id": "fw",
                "role": "gray-firewall",
                "interfaces": [],
                "boundary_flows": [
                    {
                        "source": "10.0.0.1/32",
                        "destination": "10.1.0.1/32",
                        "ingress": "in",
                        "egress": "out",
                    }
                ],
            },
        ]
        source = {"devices": devices}
        observations = {
            (d["id"], "interfaces"): '[{"ifname":"in"},{"ifname":"out"}]'
            for d in devices
        }
        observations.update(
            {
                (d["id"], "filters4"): "*filter\n:FORWARD DROP [0:0]\nCOMMIT\n"
                for d in devices
            }
        )
        policy = {
            "httpServicePorts": [80],
            "innerRevocationHttp": [
                {
                    "firewall": "fw",
                    "inner": "gw1",
                    "responder": "10.2.0.8",
                    "port": 8080,
                    "ingress": "in",
                    "egress": "out",
                }
            ],
        }
        with (
            TemporaryDirectory() as tmp,
            patch("scale.service_policy.raw_observations", return_value=observations),
        ):
            root = Path(tmp)
            (root / "spec.json").write_text(json.dumps(source))
            (row,) = service_input(root, source, {"routes": []}, policy)["chains"]
        queries = [q for q in row["queries"] if q["clause"] == "MSC-PF-25"]
        permits = [q["scope"] for q in queries if q["mustPermit"]]
        self.assertEqual(len(permits), 2)
        client, server = 0x0A000001, 0x0A020008
        request, reply = permits
        self.assertEqual(
            [request[i][0] for i in (0, 1, 3, 5, 6)], [client, server, 8080, 1, 2]
        )
        self.assertEqual(
            [reply[i][0] for i in (0, 1, 2, 5, 6)], [server, client, 8080, 2, 1]
        )
        limits = [q for q in queries if not q["mustPermit"]]
        self.assertEqual(len(limits), 4)
        self.assertTrue(all(len(q["exceptions"]) == 2 for q in limits))
        self.assertEqual(
            {q["scope"][3][0] for q in row["queries"] if q["clause"] == "MSC-PF-23"},
            {500, 4500},
        )

    def test_equivalent_interface_names_multiple_links_and_unknown_zone(self):
        devices = [
            {"id": name, "interfaces": [], "role": "transport"}
            for name in ("w", "x", "y", "z")
        ]
        topo = {"devices": devices, "links": []}

        def port(name, i, peer):
            return dict(
                ifname=name,
                ifindex=i,
                link_index=peer,
                mtu=1500,
                addr_info=[],
                linkinfo={"info_kind": "veth"},
                flags=["UP", "LOWER_UP"],
            )

        obs = {
            "w": [port("en7", 7, 1)],
            "x": [port("peer", 1, 7)],
            "y": [port("edge", 3, 4)],
            "z": [port("eth9", 4, 3)],
        }
        result = capture_topology(topo, obs, {("w", "en7"): "black"})
        self.assertEqual(len(result["links"]), 2)
        self.assertEqual(
            [d["interfaces"][0]["zone"] for d in result["devices"]],
            ["black", "black", "unknown", "unknown"],
        )
        self.assertTrue(all(not d["interfaces"] for d in topo["devices"]))
        obs["z"][0]["link_index"] = 1
        with self.assertRaises(ValueError):
            capture_topology(topo, obs)

    def test_preregistered_placement_is_reproducible_and_has_the_right_population(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for f in ("left", "right"):
                panel.register(root / f, b"x" * 32)
            a = json.loads((root / "left/placement-plan.json").read_text())
            self.assertEqual(
                a, json.loads((root / "right/placement-plan.json").read_text())
            )
            self.assertEqual(len(a["cells"]), 60)
            self.assertEqual(a["cells"]["10xLevels/inner-mode"]["eligible"], 40)
            self.assertEqual(a["cells"]["10xLevels/outer-mode"]["eligible"], 2)
            self.assertEqual(a["minimum_changed_rule_position"], 2)
            for kind in panel.FIREWALL_CHAINS:
                self.assertEqual(
                    len(
                        {
                            a["cells"][n + "/" + kind]["rule_depth_third"]
                            for n in NETWORKS
                        }
                    ),
                    1,
                )
            self.assertEqual(
                {row["rule_depth_third"] for row in a["cells"].values()},
                {None, 0, 1, 2},
            )

    def test_ordered_rules_keep_their_evaluation_order_in_the_reader(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [
                {
                    "devices": [str(i)],
                    "record": {
                        "id": i,
                        "ordered_rules": ["deny", "allow"],
                        "started_at": "2026-11-26T10:00:00+00:00",
                        "ended_at": "2026-11-26T10:00:02+00:00",
                    },
                }
                for i in range(20)
            ]
            inp = {
                "views": {"raw": rows},
                "catalogue": {
                    "devices": [{"id": str(i)} for i in range(20)],
                    "links": [],
                    "views": {"raw": {}},
                },
            }

            def blob(o):
                data = gzip.compress(json.dumps(o).encode(), mtime=0)
                p = root / (hashlib.sha256(data).hexdigest() + ".json.gz")
                p.write_bytes(data)
                return p

            source = blob(inp)
            pub = blinding.neutral_bundle(source, root, b"x" * 32)
            new = json.loads(gzip.decompress((root / pub).read_bytes()))
            self.assertNotEqual(
                [r["record"]["id"] for r in new["views"]["raw"]], list(range(20))
            )
            self.assertTrue(
                all(
                    r["record"]["ordered_rules"] == ["deny", "allow"]
                    and r["record"]["ended_seconds_from_collection_start"] == 2
                    for r in new["views"]["raw"]
                )
            )
            self.assertNotIn(b"2026-11", gzip.decompress((root / pub).read_bytes()))
            inp["views"]["raw"][1]["record"]["stdout"] = "TNS-A6B412"
            with self.assertRaisesRegex(ValueError, "operator metadata"):
                blinding.neutral_bundle(blob(inp), root, b"x" * 32)

    def test_claim_scoring_rejects_a_symptom_or_a_different_device(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "measurements/Base/inner-mode"
            base.mkdir(parents=True)
            (base / "cell.json").write_text(
                '{"observed":true,"bundle":"f","anchor":"g1"}'
            )
            run = root / "trials/inner-mode/Base/astra"
            run.mkdir(parents=True)
            (run / "execution.json").write_text(
                '{"status":"completed","bundles":{"network":"f"}}'
            )
            text = b"The gateway lost connectivity."
            (run / "answer.md").write_bytes(text)
            claim = dict(
                quotation=text.decode(),
                reason="shows loss of delivery",
                evidence="saved route",
                devices=["g1"],
                classification="target",
                identified_fault="outer-mode",
            )
            review = dict(
                complete=True,
                findings=[claim],
                answer_sha256=hashlib.sha256(text).hexdigest(),
            )
            with self.assertRaisesRegex(ValueError, "actual fault"):
                record_findings(root, "Base", "inner-mode", review)
            claim["classification"] = "consequence"
            record_findings(root, "Base", "inner-mode", review)
            saved = json.loads((base / "astra-adjudication.json").read_text())
            self.assertEqual(saved["decision"], "missed")

    def test_false_alert_counts_use_all_reviewed_controls(self):
        r = [
            dict(
                complete=True,
                case="healthy-control",
                findings=[{"classification": "other_real"}],
            ),
            dict(
                complete=True,
                case="healthy-control",
                findings=[{"classification": "false_positive"}] * 2,
            ),
            dict(
                complete=True,
                case="inner-mode",
                findings=[{"classification": "unresolved"}],
            ),
        ]
        s = alert_statistics(r)
        self.assertEqual(
            (
                s["reviewed_clean"],
                s["clean_with_false_alarm"],
                s["findings"]["false_positive"],
            ),
            (2, 1, 2),
        )

    def test_reverse_routes_and_typed_matches(self):
        routes = [
            (0, 1, 0, 255, 0, 0, 20),
            (0, 2, 8, 15, 5, 0, 20),
            (0, 3, 10, 10, 8, 0, 10),
        ]
        self.assertEqual(reverse_sources(routes, 2), [(8, 9), (11, 15)])
        chain = parse_iptables_save(
            "*filter\n:FORWARD DROP [0:0]\n-A FORWARD -p tcp --dport 80 -j ACCEPT\nCOMMIT\n"
        )["FORWARD"]
        rules, default = ordered_regions(chain, ["", "outside"])
        self.assertFalse(default)
        self.assertEqual(rules[0]["region"][3], (80, 80))

    def test_lean_first_match_against_exhaustive_small_tables(self):
        from measure import typecheck

        rng = random.Random(21)
        samples = []

        def box():
            return [sorted((rng.randrange(5), rng.randrange(5))) for _ in range(2)]

        def inside(x, p):
            return all(lo <= v <= hi for (lo, hi), v in zip(x, p))

        for i in range(160):
            rules = [
                {"region": box(), "permit": rng.choice([True, False])}
                for _ in range(rng.randrange(6))
            ]
            q = dict(
                clause="test",
                scope=box(),
                exceptions=[box() for _ in range(rng.randrange(3))],
                mustPermit=rng.choice([True, False]),
            )
            fallback = rng.choice([True, False])
            expected = all(
                next((r["permit"] for r in rules if inside(r["region"], p)), fallback)
                == q["mustPermit"]
                for x in range(5)
                for y in range(5)
                for p in [(x, y)]
                if inside(q["scope"], p)
                and not any(inside(exc, p) for exc in q["exceptions"])
            )
            samples.append(
                [
                    dict(
                        device=str(i),
                        hook="forward",
                        fallback=fallback,
                        rules=rules,
                        queries=[q],
                    ),
                    expected,
                ]
            )
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prog = root / "OrderOracle.lean"
            text = (
                (HERE / "ServicePolicyChecks.lean")
                .read_text()
                .split("load_network_records chains", 1)[0]
            )
            text += 'load_network_records cases : List (Chain × Bool) from "evidence.json" ["cases"]\n'
            text += 'set_option Elab.async false\nrun_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"\n'
            text += "example : cases.all (fun (c,v) => c.queries.all (agrees c) == v) = true := by native_decide\n"
            text += 'run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"\nend TDN.Benchmark.ServicePolicy\n'
            prog.write_text(text)
            out = typecheck(
                prog, root / "out", {"cases": samples}, set(text.splitlines())
            )
            self.assertEqual(out["status"], "pass", out.get("errors"))
