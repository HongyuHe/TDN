import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from cohort import registered_profile
from scale import blinding, design, panel
from scale.observation_window import fingerprint, freeze_then_confirm, validate_window
from scale.profiles import NETWORKS, profile
from scale.report import alert_statistics, wilson_interval
from snapshot_inputs import put


def device_record(device, kind, stdout, **fields):
    return {
        "devices": [device],
        "record": dict(device_id=device, kind=kind, stdout=stdout, returncode=0, **fields),
    }


def sample_bundle():
    devices = [
        {
            "id": n,
            "role": r,
            "level": "S1",
            "interfaces": ["private-interface"],
            "peer": "intended-address",
        }
        for n, r in (("A", "admin"), ("R", "host"), ("I", "inner"))
    ]
    aw = {
        "admin": "A",
        "red": "R",
        "attached_inner": "I",
        "record": {"red_host": "R", "security_level": "S2"},
        "interface": {"alias": "MSC Red enclave security level S2"},
    }
    rows = [
        device_record(
            d["id"], "traffic-control-qdiscs", "[]", id=f"obs-{i}", command=["tc", "-j", "qdisc", "show"]
        )
        for i, d in enumerate(devices)
    ]
    rows.append(
        device_record(
            "I",
            "sas",
            "ESTABLISHED 12 minutes ago, rekeying in 300s\n  installed 700s ago",
            id="obs-5",
            raw_sha256="private-hash",
        )
    )
    views = {
        "declared-devices": [{"devices": [], "record": devices[0]}],
        "enclave-designations": [{"devices": ["A", "R", "I"], "record": aw}],
        "link-census": [{"devices": [], "record": {"reciprocal": False}}],
        "gateway-connections": [],
        "raw": rows,
        "processing": [device_record("I", "routes4", "[]", id="processing-1")],
    }
    return {
        "catalogue": {
            "devices": devices,
            "links": [{"a": "R", "b": "I"}],
            "views": {k: {} for k in views},
        },
        "views": views,
    }


def native_shape(name, control):
    config = design.control_topology(name, control)
    routes = [
        {
            "device_id": d["id"],
            "destination": r["prefix"],
            "gateway": r["via"],
            "family": 4,
            "table": "main",
            "status": "observed",
        }
        for d in config["devices"]
        for r in d.get("routes", [])
    ]
    filters = []
    for fw in (d for d in config["devices"] if d["role"] == "gray-firewall"):
        rows = [
            {
                "ordinal": i,
                "raw_text": f"-A FORWARD -i {f['ingress']} -o {f['egress']} -s {f['source']} -d {f['destination']} -p esp -j ACCEPT",
            }
            for i, f in enumerate(fw["boundary_flows"])
        ]
        filters.append(
            {
                "device_id": fw["id"],
                "family": 4,
                "table": "filter",
                "chain": "FORWARD",
                "ordered_rules": rows,
            }
        )
    for device, rotation in design.filter_rotations(config["devices"], design.CONTROLS.index(control)).items():
        for hook in ("INPUT", "FORWARD"):
            lines = [f"-A {hook} -p {p} -j ACCEPT" for p in ("tcp", "udp", "esp", "icmp")]
            rows = [{"ordinal": i, "raw_text": row} for i, row in
                    enumerate(design.healthy_rule_order(lines, rotation))]
            filters.append(dict(device_id=device, family=4, table="filter", chain=hook, ordered_rules=rows))
    return config, {
        "devices": [{"id": d["id"], "role": d["role"]} for d in config["devices"]],
        "routes": routes,
        "filters": filters,
        "links": [],
        "interfaces": [],
        "tunnels": [],
        "observations": [],
    }


class RegisteredBenchmark(unittest.TestCase):
    def test_seed_freezes_coverage_topologies_and_policy(self):
        with TemporaryDirectory() as tmp:
            study = Path(tmp) / "study"
            panel.register(study, b"1" * 32)
            protocol = json.loads((study / "protocol.json").read_bytes())
            plan = json.loads((study / "placement-plan.json").read_bytes())
            self.assertEqual(3, protocol["method_version"])
            self.assertEqual(20, len(protocol["cases"]))
            self.assertEqual(60, len(plan["cells"]))
            self.assertEqual(9, sum(len(x) for x in plan["controls"].values()))
            coverage = protocol["clause_cases"]
            self.assertEqual((53, 23), (len(coverage), sum(bool(v) for v in coverage.values())))
            self.assertEqual(
                20, sum(bool(v) for v in design.clause_coverage(design.cases_for({})).values())
            )
            self.assertEqual(["MSC-PF-10"], plan["deployment_policies"]["Base"]["selected_objectives"])
            self.assertEqual(40, plan["cells"]["10xLevels/outer-outbound-protection"]["eligible"])
            for n in NETWORKS:
                choices = [plan["cells"][n + "/" + c.key]["control_variant"] for c in design.CASES]
                self.assertEqual(sorted(choices.count(k) for k in design.CONTROLS), [6, 7, 7])
                self.assertEqual(choices, [plan["cells"]["Base/" + c.key]["control_variant"] for c in design.CASES])

    def test_healthy_variation_preserves_forwarding_and_is_observed(self):
        for n in NETWORKS:
            original = profile(n)["topology"]
            configured = []
            for k in design.CONTROLS:
                with self.subTest(network=n, control=k):
                    spec, snap = native_shape(n, k)
                    self.assertTrue(registered_profile(design.control_profile(n, k)))
                    self.assertEqual(spec["links"], original["links"])
                    design.validate_control_shape(n, k, snap, spec, healthy=True)
                    for device, route in design.additional_routes(original, k):
                        dev = next(d for d in original["devices"] if d["id"] == device)
                        self.assertTrue(
                            any(
                                design.ip_network(route["prefix"]).subnet_of(
                                    design.ip_network(r["prefix"])
                                )
                                and route["via"] == r["via"]
                                for r in dev["routes"]
                            )
                        )
                    for new, old in zip(spec["devices"], original["devices"]):
                        if old["role"] == "gray-firewall":
                            self.assertCountEqual(old["boundary_flows"], new["boundary_flows"])
                    configured.append((spec, snap))
            spec, snapshot = configured[0]
            with self.assertRaisesRegex(ValueError, "forwarding entries"):
                design.validate_control_shape(n, design.CONTROLS[1], snapshot, None, healthy=False)
            snapshot["filters"][0]["ordered_rules"].reverse()
            with self.assertRaisesRegex(ValueError, "order"):
                design.validate_control_shape(n, design.BASE_CONTROL, snapshot, spec, healthy=True)

    def test_public_bundle_contains_only_device_observations_and_policy(self):
        with TemporaryDirectory() as t:
            root = Path(t)
            original = sample_bundle()
            packed = gzip.compress(json.dumps(original).encode(), mtime=0)
            private = root / (hashlib.sha256(packed).hexdigest() + ".json.gz")
            private.write_bytes(packed)
            public = blinding.neutral_bundle(
                private, root / "public", b"a" * 32, policy={"selected_objectives": ["MSC-PF-10"]}
            )
            data = json.loads(gzip.decompress((root / "public" / public).read_bytes()))
            self.assertEqual(set(data["views"]), {"raw", "processing", "deployment-policy"})
            self.assertNotIn("links", data["catalogue"])
            self.assertEqual(
                {d["id"]: d.get("levels", d.get("level")) for d in data["catalogue"]["devices"]},
                {"R": "S2", "I": ["S2"], "A": "S1"},
            )
            for forbidden in (
                "intended-address",
                "private-hash",
                "private-interface",
                "reciprocal",
                "300s",
                "700s",
                'obs-5"',
            ):
                self.assertNotIn(forbidden, json.dumps(data))
            self.assertIn("ESTABLISHED", json.dumps(data))
            self.assertEqual(private.read_bytes(), packed)
            original["views"]["enclave-designations"][0]["record"]["interface"]["alias"] = "S1"
            with self.assertRaisesRegex(ValueError, "designation"):
                blinding.observation_view(original, {})

    def test_only_measurement_fields_are_removed(self):
        def project(low, high):
            self.assertEqual(blinding.measurement_text("sas", low), blinding.measurement_text("sas", high))

        project("0 bytes_i, 0 bytes_o", "1234 bytes_i (12 pkts, 5s ago), 6798 bytes_o (98 pkts)")
        project("    in  aa123456,      0 bytes,  0 packets",
                "    in  aa123456,   2409 bytes, 42 packets, 5s ago")
        project("installed reqid=81 bytes-in=0 bytes-out=0 packets-in=0 packets-out=0",
                "installed reqid=81 bytes-in=1234 bytes-out=6599 packets-in=12 packets-out=80")
        public = blinding.measurement_text("sas", '{"bytes-in":6599,"packets-out":"80","reqid":81}')
        self.assertEqual(json.loads(public), {"bytes-in":"[count omitted]", "packets-out":"[count omitted]", "reqid":81})
        for kind in ("states", "convergence-states", "xfrm-states-detailed-nokeys"):
            source = "lifetime config:\n  limit: hard 111(bytes)\nlifetime current:\n  464(bytes), 9(packets)"
            clean = blinding.measurement_text(kind, source)
            self.assertIn("111(bytes)", clean)
            self.assertNotIn("464", clean)
            self.assertNotIn("9(packets)", clean)
        for kind in ("filters4", "convergence-filters6"):
            output = ":INPUT DROP [12:300]\n[15:200] -A INPUT -p tcp --dport 443 -c 15 200 -j DROP"
            clean = blinding.measurement_text(kind, output)
            self.assertNotIn("200", clean)
            self.assertIn("INPUT DROP", clean)
            self.assertIn("--dport 443", clean)
        expr = {
            "nftables": [
                {
                    "rule": {
                        "expr": [{"counter": {"packets": 13, "bytes": 220}}, {"quota": {"bytes": 220}}]
                    }
                }
            ]
        }
        values = json.loads(blinding.measurement_text("nft-hooks", json.dumps(expr)))["nftables"][0][
            "rule"
        ]["expr"]
        self.assertEqual(values, [{"counter": {}}, {"quota": {"bytes": 220}}])
        self.assertEqual(
            "rekey_time = 50m", blinding.measurement_text("loaded-public-config", "rekey_time = 50m")
        )
        xfrm = "expire add: soft 100(sec), hard 200(sec)\n  add 2026-11-25 00:00:00 use -"
        self.assertIn("soft 100", blinding.measurement_text("xfrm-states-detailed-nokeys", xfrm))
        self.assertNotIn("2026", blinding.measurement_text("states", xfrm))

    def test_inner_gateways_share_one_inventory_schema(self):
        bundle = sample_bundle()
        for name, role in (("R2", "host"), ("I2", "inner")):
            bundle["catalogue"]["devices"].append(dict(id=name, role=role, level="S1"))
            bundle["views"]["raw"].append(device_record(name, "traffic-control-qdiscs", "[]"))
        second = dict(admin="A", red="R2", attached_inner="I",
                      record={"red_host": "R2", "security_level": "S1"},
                      interface={"alias": "MSC Red enclave security level S1"})
        bundle["views"]["enclave-designations"].append({"devices": ["A", "R2", "I"], "record": second})

        def inventory():
            return {d["id"]: d for d in blinding.observation_view(bundle, {})["catalogue"]["devices"]
                    if d["role"] == "inner"}

        shared = inventory()
        self.assertEqual(shared["I"]["levels"], ["S1", "S2"])
        self.assertEqual(shared["I2"]["levels"], [])
        second["attached_inner"] = "I2"
        separate = inventory()
        self.assertEqual(separate["I"]["levels"], ["S2"])
        self.assertEqual(separate["I2"]["levels"], ["S1"])
        self.assertTrue(all(set(d) == {"id", "role", "levels"} for d in (*shared.values(), *separate.values())))

    def test_control_permutations_preserve_chain_verdicts_and_barriers(self):
        from scale.control_filters import healthy_filter_table
        text = ('*filter\n:INPUT DROP [0:0]\n'
                '-A INPUT -p tcp -j ACCEPT\n-A INPUT -p udp -j ACCEPT\n-A INPUT -p icmp -j ACCEPT\n'
                '-A INPUT -p tcp -j DROP\n-A INPUT -m limit --limit 1/s -j ACCEPT\n'
                '-A INPUT -p esp -j ACCEPT\n-A INPUT -p udp -j ACCEPT\nCOMMIT\n')
        original = text.splitlines()
        alternatives = [healthy_filter_table(text, i) for i in (0, 1, 2)]
        self.assertGreater(len(set(alternatives)), 1)
        for i, rendered in enumerate(alternatives):
            self.assertEqual(healthy_filter_table(rendered, i), rendered)
            self.assertCountEqual(rendered.splitlines(), original)
            self.assertEqual(rendered.splitlines()[:3], original[:3])
            self.assertEqual(rendered.splitlines()[5:7], original[5:7])

    def test_signatures_are_evaluated_in_context_and_missing_tc_is_unknown(self):
        for prefix in ("192.0.2", "198.51.100", "203.0.113"):
            for address in (prefix + ".0/24", prefix + ".9", prefix + ".123/32", prefix + ".255"):
                self.assertTrue(blinding.fixture_signature("sas", address))
        for address in ("192.0.20.1", "192.0.2.256", "1192.0.2.1", "198.51.101.1", "203.0.112.255"):
            self.assertIsNone(blinding.fixture_signature("routes4", address))
        mixed = sample_bundle()
        mixed["views"]["raw"][0]["record"]["stderr"] = "peer 198.51.100.90"
        with self.assertRaisesRegex(ValueError, "RFC 5737"):
            blinding.observation_view(mixed, {})
        self.assertIsNone(blinding.fixture_signature("routes4", "table 253"))
        self.assertIsNone(blinding.fixture_signature("filters4", "[39101:253] -A INPUT -j DROP"))
        for kind, value in (
            ("routes4", "192.0.2.245/32"),
            ("filters4", "-A INPUT -p 253 -j ACCEPT"),
            ("filters6", "-A INPUT -p udp --dport 39106 -j ACCEPT"),
            ("traffic-control-filters", '[{"kind":"matchall","options":{"action":"drop"}}]'),
        ):
            self.assertTrue(blinding.fixture_signature(kind, value))
        rows = [device_record("R", "traffic-control-qdiscs", '[{"dev":"eth0","kind":"clsact"}]')]
        with self.assertRaisesRegex(ValueError, "Missing"):
            blinding.validate_traffic_control(rows, {"R"})
        for mode in ("ingress", "egress"):
            rows.append(
                device_record(
                    "R",
                    "traffic-control-filters",
                    "[]",
                    command=["tc", "filter", "show", "dev", "eth0", mode],
                )
            )
        blinding.validate_traffic_control(rows, {"R"})

    def test_witness_requires_actual_forwarding_and_three_distinct_recordings(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            r = {
                "case": "inner-outbound-protection",
                "anchor": "I",
                "readings": {},
                "facts": {
                    "ingress_zone": "Red",
                    "egress_zone": "Gray",
                    "ingress_layers": [],
                    "egress_layers": [],
                    "source_level": "S1",
                    "red_origin": True,
                    "control_traffic": False,
                    "forwarded": True,
                    "ingress_payload_id": "p",
                    "egress_payload_id": "p",
                },
            }
            for phase in ("before", "during", "restored"):
                path = root / (phase + ".txt")
                path.write_text(phase)
                r["readings"][phase] = {
                    "file": path.name,
                    "sha256": fingerprint(path),
                    "violated": phase == "during",
                }

            def check():
                design.validate_case_observation(r["case"], "I", "S1", json.dumps(r), root, root)

            check()
            r["facts"]["forwarded"] = False
            with self.assertRaisesRegex(ValueError, "behavior"):
                check()
            r["facts"]["forwarded"] = True
            r["readings"]["during"]["file"] = "../escape"
            with self.assertRaisesRegex(ValueError, "recording"):
                check()

    def test_control_statistics_count_each_variant(self):
        reviews = [dict(network="Base", case=k, complete=True, findings=[]) for k in design.CONTROLS]
        reviews[1]["findings"] = [{"classification": "false_positive"}]
        stats = alert_statistics(reviews)
        self.assertEqual((3, 1), (stats["reviewed_clean"], stats["clean_with_false_alarm"]))
        self.assertIsNone(wilson_interval(0, 0))
        self.assertAlmostEqual(wilson_interval(0, 9)[1], 0.29915, places=4)

    def test_only_device_output_counts_as_reading_a_capture(self):
        from run_snapshot_audits import read_device_output

        row = {
            "tool": "observe",
            "ok": True,
            "arguments": {"view": "deployment-policy"},
            "returned_characters": 123,
        }
        self.assertFalse(read_device_output([row]))
        row["arguments"] = {"view": "raw", "fields": ["id"]}
        self.assertFalse(read_device_output([row]))
        row["arguments"] = {"view": "processing", "fields": ["stdout"]}
        self.assertTrue(read_device_output([row]))
        row["returned_characters"] = 0
        self.assertFalse(read_device_output([row]))

    def test_path_confirmation_checks_every_observed_hop(self):
        with TemporaryDirectory() as t:
            root = Path(t)
            source = root / "snapshot.json"
            path = [["a:x", "m:left"], ["m:right", "b:y"]]
            snap = {
                "devices": [
                    {"id": "a", "role": "inner", "security_level_id": "level-a"},
                    {"id": "m", "role": "transport"},
                    {"id": "b", "role": "inner", "security_level_id": "level-b"},
                ],
                "interfaces": [
                    {
                        "id": v,
                        "device_id": v.split(":")[0],
                        "status": "observed",
                        "observed_up": True,
                        "zone": "gray",
                    }
                    for edge in path
                    for v in edge
                ],
                "links": [
                    {
                        "endpoint_interface_ids": edge,
                        "relation": "veth",
                        "status": "observed",
                        "runtime_peer_check": {"verified": True},
                    }
                    for edge in path
                ],
            }

            def check():
                source.write_text(json.dumps(snap))
                design.validate_path_observation(
                    "gray-cross-level-path", "a", json.dumps({"path": path}), root
                )

            check()
            snap["devices"][1]["role"] = "gray-firewall"
            with self.assertRaisesRegex(ValueError, "traverses"):
                check()
            snap["devices"][1]["role"] = "transport"
            snap["links"][0]["runtime_peer_check"]["verified"] = False
            with self.assertRaisesRegex(ValueError, "unobserved"):
                check()

    def test_legacy_fixture_refuses_first_row_edit_before_opening_a_device(self):
        with patch.object(sys, "path", [str(HERE / "scale"), *sys.path]):
            from scale import fixtures
        with patch.object(fixtures, "Replica", side_effect=AssertionError("opened a device")):
            with self.assertRaisesRegex(ValueError, "replay-only"):
                fixtures.handle(
                    {"network": "Base", "case": fixtures.WEB, "action": "edit", "nonce": "0" * 16}
                )
        with self.assertRaisesRegex(ValueError, "inspection and rollback"):
            fixtures.acl(("device", "INPUT", []), "-I", "ACCEPT")

    def test_correlated_evidence_and_selected_objectives(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            readings = {}
            for phase in ("before", "during", "restored"):
                file = root / (phase + ".log")
                file.write_text(phase)
                readings[phase] = {
                    "file": file.name,
                    "sha256": fingerprint(file),
                    "violated": phase == "during",
                }

            def check(case, facts, anchor="O"):
                witness = {"case": case, "anchor": anchor, "facts": facts, "readings": readings}
                design.validate_case_observation(case, anchor, "S1", json.dumps(witness), root, root)

            gate = {"pf10_selected": False, "ipv4_header_words": 7, "accepted": True}
            with self.assertRaisesRegex(ValueError, "behavior"):
                check("outer-ipv4-options", gate)
            gate["pf10_selected"] = True
            check("outer-ipv4-options", gate)
            spec = {
                "filters": [dict(table="filter", chain="INPUT", device_id="O", family=4, policy="drop")]
            }
            (root / "snapshot.json").write_text(json.dumps(spec))
            fallback = {
                "zone": "Gray",
                "matched_explicit_rule": False,
                "default_policy": "ACCEPT",
                "approved": False,
                "accepted": True,
                "chain": "INPUT",
            }
            with self.assertRaisesRegex(ValueError, "behavior"):
                check("outer-gray-default-admission", fallback)
            spec["filters"][0]["policy"] = "accept"
            (root / "snapshot.json").write_text(json.dumps(spec))
            check("outer-gray-default-admission", fallback)
            layers = {
                k: dict(device=d, active=True, origin="provider", key_context="ctx-1")
                for k, d in (("inner", "I"), ("outer", "O"))
            }
            native = {
                "devices": [{"id": "I", "role": "inner"}, {"id": "O", "role": "outer"}],
                "observations": [],
            }
            (root / "snapshot.json").write_text(json.dumps(native))
            with self.assertRaisesRegex(ValueError, "public key-origin"):
                check("shared-layer-key-context", layers, "I")
            for i, layer in enumerate(layers.values()):
                rel = f"raw/obs-{i}.json"
                put(root / rel, {"stdout": json.dumps(layer)})
                native["observations"].append(
                    {
                        "device_id": layer["device"],
                        "kind": "public-key-context",
                        "returncode": 0,
                        "raw_path": rel,
                        "raw_sha256": fingerprint(root / rel),
                    }
                )
            (root / "snapshot.json").write_text(json.dumps(native))
            check("shared-layer-key-context", layers, "I")
            layers["outer"]["key_context"] = "same-issuer-different-context"
            with self.assertRaisesRegex(ValueError, "behavior"):
                check("shared-layer-key-context", layers, "I")

    def test_preflight_qualifies_three_distinct_controls_before_any_fault_is_available(self):
        from delivery_lab import intended_pairs

        with TemporaryDirectory() as t, patch.object(panel, "NETWORKS", {"Base": NETWORKS["Base"]}):
            root = Path(t)
            study = root / "run"
            panel.register(study, b"2" * 32)
            for k in design.CONTROLS:
                dest = root / k
                spec, snapshot = native_shape("Base", k)

                def collect():
                    dest.mkdir()
                    snap = dest / "snapshot"
                    native = snap / "native"
                    put(dest / "capture.json", {"converged": True, "control_variant": k})
                    put(snap / "spec.json", spec)
                    put(native / "spec.json", spec)
                    declarations = []
                    from scale.level_policy import bindings

                    for red, inner, aw, level in bindings(spec):
                        declarations.append(
                            {
                                "red": red,
                                "admin": aw,
                                "attached_inner": inner,
                                "record": {"red_host": red, "security_level": level},
                                "interface": {"alias": "MSC Red enclave security level " + level},
                            }
                        )
                    put(snap / "enclave-policy.json", declarations)
                    for device in spec["devices"]:
                        dev = device["id"]
                        outputs = [
                            ("routes4", [r for r in snapshot["routes"] if r["device_id"] == dev]),
                            ("traffic-control-qdiscs", []),
                        ]
                        if device["role"] in {"inner", "outer"}:
                            outputs.append(("public-key-context", dict(device=dev, active=True,
                                            origin="test-provider", key_context=device["role"])))
                        for kind, answer in outputs:
                            key = f"obs-{len(snapshot['observations']) + 1}"
                            rel = "raw/" + key + ".json"
                            cmd = (
                                ["tc", "-j", "qdisc", "show"]
                                if kind.startswith("traffic")
                                else ["ip", "-j", "route"]
                            )
                            put(native / rel, {"stdout": json.dumps(answer), "stderr": ""})
                            snapshot["observations"].append(
                                dict(
                                    id=key,
                                    device_id=dev,
                                    kind=kind,
                                    command=cmd,
                                    raw_path=rel,
                                    raw_sha256=fingerprint(native / rel),
                                    returncode=0,
                                )
                            )
                    put(native / "snapshot.json", snapshot)
                    put(
                        native / "manifest.json",
                        {
                            "files": [
                                {"path": str(p.relative_to(native)), "sha256": fingerprint(p)}
                                for p in sorted(native.rglob("*.json"))
                            ]
                        },
                    )
                    proc = snap / "processing/observations.json"
                    put(
                        proc,
                        {
                            "records": [
                                {
                                    "id": "processing-1",
                                    "device_id": spec["devices"][0]["id"],
                                    "kind": "routes4",
                                    "stdout": "[]",
                                    "returncode": 0,
                                }
                            ]
                        },
                    )
                    put(
                        snap / "processing/manifest.json",
                        {"files": [{"path": "observations.json", "sha256": fingerprint(proc)}]},
                    )

                def confirm():
                    rows = [
                        {"source": a, "destination": b, "delivered": True}
                        for a, b, _ in intended_pairs({"topology": spec})
                    ]
                    sessions = [
                        {"device": d["id"], "established": True, "installed": True}
                        for d in spec["devices"]
                        if d["role"] in ("inner", "outer")
                    ]
                    path = dest / "control-health.json"
                    put(
                        path,
                        {
                            "ready": True,
                            "delivery": rows,
                            "tunnels": {"before": sessions, "after": sessions, "attempted": []},
                        },
                    )
                    return path

                freeze_then_confirm(dest, panel.BACKGROUND_PLAN, collect, confirm)
            pool = root / "captures.json"
            put(pool, {"controls": {"Base": {k: k for k in design.CONTROLS}}, "trials": []})
            with self.assertRaisesRegex(ValueError, "outstanding"):
                panel.prepare(study, pool)
            errors = json.loads((study / "panel-preflight.json").read_bytes())["errors"]
            self.assertEqual(len(errors), 20)
            self.assertTrue(
                all(e[2] == "Missing independently captured location" for e in errors), errors
            )
            self.assertFalse((study / "approved-panel.json").exists())
            public = list((study / "raw").glob("*.gz"))
            self.assertEqual(len(public), 3)
            for blob in public:
                views = json.loads(gzip.decompress(blob.read_bytes()))["views"]
                self.assertEqual(set(views), {"raw", "processing", "deployment-policy"})
            self.check_complete_small_study(root, pool)
            amended = dest / "snapshot/enclave-policy.json"
            amended.write_bytes(amended.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "frozen"):
                validate_window(dest, fingerprint(panel.BACKGROUND_PLAN), require_metadata=True)

    def check_complete_small_study(self, root, pool):
        case = next(c for c in design.CASES if c.key == "inner-mode")
        study = root / "small-study"
        capture = root / "fault" / "capture"
        operator = capture.parent / "operator"
        with patch.object(panel, "CASES", (case,)), patch.object(design, "CASES", (case,)):
            panel.register(study, b"3" * 32)
            target = json.loads((study / "placement-plan.json").read_bytes())["cells"]["Base/inner-mode"]
            anchor = target["anchor"]

            def collect():
                shutil.copytree(root / target["control_variant"] / "snapshot", capture / "snapshot")
                put(capture / "capture.json", {"converged": True, "control_variant": target["control_variant"]})
                native = capture / "snapshot/native"
                f = native / "snapshot.json"
                state = json.loads(f.read_bytes())
                obs = "obs-9999"
                raw = native / "raw" / (obs + ".json")
                put(raw, {"stdout": "protected child mode: TRANSPORT", "stderr": ""})
                state["observations"].append(
                    dict(
                        id=obs,
                        device_id=anchor,
                        kind="connections-raw",
                        command=["swanctl", "--list-conns"],
                        raw_path="raw/" + raw.name,
                        raw_sha256=fingerprint(raw),
                        returncode=0,
                    )
                )
                f.write_text(json.dumps(state))
                manifest = native / "manifest.json"
                items = [p for p in native.rglob("*.json") if p != manifest]
                manifest.write_text(
                    json.dumps(
                        {
                            "files": [
                                {"path": str(p.relative_to(native)), "sha256": fingerprint(p)}
                                for p in items
                            ]
                        }
                    )
                )

            def confirm():
                out = operator / "reading.json"
                put(out, {"device": anchor, "protected_child_mode": "TRANSPORT"})
                return out

            freeze_then_confirm(capture, panel.BACKGROUND_PLAN, collect, confirm)
            put(capture.parent / "cell.json", {"network": "Base", "case": case.key, "observed": True})
            put(capture.parent / "post-health.json", {"ready": True})
            candidate = json.loads(pool.read_bytes())
            candidate["trials"] = [
                dict(
                    network="Base",
                    case=case.key,
                    control_variant=target["control_variant"],
                    anchor=anchor,
                    level=target["level"],
                    trial="fault",
                    location_evidence="operator/reading.json",
                    location_sha256=fingerprint(operator / "reading.json"),
                )
            ]
            source = root / "small-input.json"
            variant = target["control_variant"]
            candidate["trials"][0]["control_variant"] = next(k for k in design.CONTROLS if k != variant)
            put(root / "mismatched.json", candidate)
            with self.assertRaisesRegex(ValueError, "outstanding"):
                panel.prepare(study, root / "mismatched.json")
            self.assertFalse((study / "approved-panel.json").exists())
            candidate["trials"][0]["control_variant"] = variant
            put(source, candidate)
            panel.prepare(study, source)
            seal = panel.approved_panel(study)
            self.assertEqual(set(seal["inputs"]), {"Base/" + k for k in (*design.CONTROLS, case.key)})
            self.assertEqual(set(seal["sources"]), set(seal["inputs"]))
            paths = {}

            def fake_lean(proof_root, network, snapshot, dest, *, control, registered_policy, control_variant):
                from scale.verification import REGISTERED_PROOF_SUITES
                self.assertIn("MSC-PF-10", registered_policy["selected_objectives"])
                if not control:
                    self.assertEqual(control_variant, variant)
                paths[snapshot] = proof_root
                reject = design.CONTROLS[1] in str(snapshot)
                checks = {
                    key: {
                        "status": "rejected" if reject else "pass",
                        "source_sha256": "fixed",
                        "failed_obligations": ["example"] if reject else [],
                    } for key in REGISTERED_PROOF_SUITES
                }
                put(dest / "verification.json", checks)
                return checks

            with patch("scale.verification.verify", side_effect=fake_lean):
                panel.verify_panel(study, workers=1)
            self.assertEqual(paths[(capture / "snapshot").resolve()], design.control_run_root(study, "Base", variant))
            for k, verdict in zip(design.CONTROLS[1:], ("false_alarm", "accepted")):
                cell = study / "measurements/Base" / k
                self.assertEqual(paths[(root / k / "snapshot").resolve()], cell / "control-run")
                self.assertEqual(json.loads((cell / "tdn-control.json").read_bytes())["status"], verdict)
