import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from scale.design import deployment_policy
from scale.service_policy import check as check_services
from scale.verification import check_key_contexts, verify
from full_suite import prepare_template
from measure import typecheck
from tdn_evidence.parsers.execution import empty_device, rule_json


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value).encode()
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def policy_fixture(folder, change):
    def device(name, role, interfaces, **settings):
        return dict(id=name, role=role, interfaces=[dict(name=k, zone=z) for k, z in interfaces], **settings)

    a, b = "10.0.1.1", "10.0.2.1"
    devices = [
        device("I1", "inner", [("gray", "gray")], level="S1", tunnel=dict(local=a, remote=b, peer="I2")),
        device("I2", "inner", [("gray", "gray")], level="S1", tunnel=dict(local=b, remote=a, peer="I1")),
        device("GF", "gray-firewall", [("left", "gray"), ("right", "gray"), ("mgmt", "management")],
               boundary_flows=[dict(source=a+"/32", destination=b+"/32", ingress="left", egress="right")]),
        device("O", "outer", [("gray", "gray"), ("black", "black")],
               tunnel=dict(peer="O-peer", local="10.0.3.1", remote="10.0.4.1",
                           flows=[dict(inside="gray", local=a+"/32", remote=b+"/32")])),
    ]
    intent = {"devices": devices}
    snapshot = {"devices": [dict(id=d["id"], namespace=d["id"], role=d["role"]) for d in devices],
                "observations": []}
    files = []
    def emit(relative, value):
        files.append(dict(path=relative, sha256=save(folder / relative, value)))
        return files[-1]["sha256"]

    guard = '-m u32 --u32 "0x0>>0x18&0xf=0x5"'
    for d in devices:
        name = d["id"]
        fallback = "ACCEPT" if name == "O" and change in ("default", "shadowed-default") else "DROP"
        rows = ["*filter", f":INPUT {fallback} [0:0]", ":FORWARD DROP [0:0]", ":OUTPUT DROP [0:0]"]
        if name == "GF":
            rows.append(f"-A FORWARD -i left -o right -s {a}/32 -d {b}/32 -p udp -m multiport --dports 500,4500 -j ACCEPT")
            iface = "left" if change == "management" else "mgmt"
            rows.append(f"-A INPUT -i {iface} -p tcp --dport 8443 -j ACCEPT")
        if name == "O":
            if change == "shadowed-default":
                rows.append("-A INPUT -j DROP")
            header = "" if change == "options" else guard
            if change == "explicit-options":
                header = guard.replace("=0x5", "=0xf")
            rows.append(f"-A INPUT -i black -p esp {header} -j ACCEPT")
            src = "10.0.8.1" if change == "source" else a
            rows.append(f"-A FORWARD -i gray -o black -s {src}/32 -d {b}/32 -p esp "
                        f"-m policy --dir out --pol ipsec --reqid 2 --mode tunnel {guard} -j ACCEPT")
        rows.append("COMMIT")
        for kind, command, stdout in (
            ("interfaces", ["ip", "-j", "-d", "address", "show"],
             json.dumps([{"ifname": p["name"]} for p in d["interfaces"]])),
            ("filters4", ["iptables-save", "-t", "filter"], "\n".join(rows)),
        ):
            relative = "raw/obs-" + str(len(files)) + ".json"
            digest = emit(relative, dict(stdout=stdout, stderr=""))
            snapshot["observations"].append(dict(device_id=name, kind=kind, raw_path=relative,
                raw_sha256=digest, returncode=0, parse_status="parsed", command=["docker", "exec", name, *command]))
    emit("spec.json", intent)
    emit("snapshot.json", snapshot)
    save(folder / "manifest.json", dict(files=files, convergence={"consistent": True}))
    forwarding = {"portIds": {"O:gray": 1}, "routes": [dict(ingress=1, egress=1,
        destPrefixLow=0x0a000100, destPrefixHigh=0x0a0001ff, prefixLength=24, metric=0, tablePriority=1)]}
    return intent, forwarding


class RegisteredCheckerCoverage(unittest.TestCase):
    def test_forwarding_program_checks_each_encapsulation_boundary(self):
        ifaces = [dict(owner=owner, name=name, stack=stack, canOriginateTraffic=(i == 0))
                  for i, (owner, name, stack) in enumerate([
                      (0, "red", []), (1, "red", []), (1, "gray", [1]),
                      (2, "gray", [1]), (2, "black", [2, 1])])]
        with TemporaryDirectory() as t:
            base = Path(t)
            source = prepare_template("SnapshotCompliance.lean", base)
            for case in ("healthy", "inner", "outer"):
                with self.subTest(case=case):
                    devices = [empty_device() for _ in range(3)]
                    for device, role, inside, outside in ((1, "inner", "red", "gray"), (2, "outer", "gray", "black")):
                        tokens = ["-i", inside, "-o", outside]
                        if case != role:
                            tokens.extend(["-m", "policy", "--dir", "out", "--pol", "ipsec",
                                           "--reqid", str(device), "--mode", "tunnel"])
                        devices[device]["forwardRules"] = [rule_json(dict(
                            action="accept", ordinal=0, raw_text=" ".join(tokens),
                            matches={"iptables_tokens": tokens}))]
                    evidence = dict(devices=devices, ports=ifaces, routes=[], bridges=[], links=[[0,1],[2,3]],
                                    redSources=[0], grayIfaces=[2,3], blackIfaces=[4])
                    result = typecheck(source, base / case, evidence, set(source.read_text().splitlines()))
                    self.assertEqual(result["status"], "pass" if case == "healthy" else "rejected", result["errors"])
                    if case != "healthy":
                        self.assertIn("forward_checks", " ".join(result["failed_obligations"]))

    def test_registered_verifier_runs_key_and_filter_checks_on_the_same_snapshot(self):
        with TemporaryDirectory() as t:
            root = Path(t)
            snapshot = root / "network"
            native = snapshot / "native"
            intent, forwarding = policy_fixture(native, "options")
            data = json.loads((native / "snapshot.json").read_bytes())
            manifest = json.loads((native / "manifest.json").read_bytes())
            for i, d in enumerate(x for x in intent["devices"] if x["role"] in ("inner","outer")):
                path = f"raw/obs-{100 + i}.json"
                record = dict(device=d["id"], active=True, origin="provider", key_context="same")
                digest = save(native / path, dict(stdout=json.dumps(record), stderr=""))
                manifest["files"].append(dict(path=path, sha256=digest))
                data["observations"].append(dict(device_id=d["id"], kind="public-key-context",
                                                 returncode=0, raw_path=path, raw_sha256=digest))
            for item in manifest["files"]:
                if item["path"] == "snapshot.json":
                    item["sha256"] = save(native / "snapshot.json", data)
            save(native / "manifest.json", manifest)

            def imported_routes(_native, _processing, out):
                save(out / "forwarding/evidence.json", forwarding)
                return {}

            with (patch("scale.verification.profile", return_value={"topology": intent}),
                  patch("scale.verification.suite", side_effect=imported_routes)):
                result = verify(root, "test", snapshot, root / "verifier", registered_policy=deployment_policy(intent))
            for name, obligation in (("key-contexts", "active_layers_have_distinct_key_contexts"),
                                     ("service-policy", "selected_outer_ipv4_options_are_dropped")):
                self.assertEqual(result[name]["status"], "rejected", result[name])
                self.assertIn(obligation, " ".join(result[name]["failed_obligations"]))

    def test_raw_filters_and_routes_reach_named_lean_checks(self):
        cases = {
            "healthy": None, "shadowed-default": None, "options": "selected_outer_ipv4_options_are_dropped",
            "explicit-options": "selected_outer_ipv4_options_are_dropped",
            "default": "outer_gray_denies_unapproved_traffic", "source": "outer_gray_checks_source_interface",
            "management": "gray_management_requires_management_interface", "unselected-options": None,
        }
        with TemporaryDirectory() as t:
            for case, obligation in cases.items():
                with self.subTest(case=case):
                    base = Path(t) / case
                    native = base / "native"
                    intent, forwarding = policy_fixture(native, "options" if case == "unselected-options" else case)
                    policy = deployment_policy(intent)
                    if case == "unselected-options":
                        policy["selected_objectives"] = []
                    result = check_services(native, intent, forwarding, base / "check", registered_policy=policy)
                    self.assertEqual(result["status"], "rejected" if obligation else "pass", result["errors"])
                    if obligation:
                        self.assertIn(obligation, " ".join(result["failed_obligations"]))

    def test_key_manager_observations_reach_lean_with_integrity_and_coverage_checks(self):
        devices = [dict(id="I", role="inner"), dict(id="O", role="outer")]
        with TemporaryDirectory() as t:
            base = Path(t)
            for case in ("distinct", "shared", "missing", "corrupt", "inactive", "distinct-origins"):
                with self.subTest(case=case):
                    observations = []
                    for i, device in enumerate(devices):
                        if case == "missing" and i:
                            continue
                        relative = f"raw/obs-{i}.json"
                        record = dict(device=device["id"], active=case != "inactive" or not i,
                                      origin=device["id"] if case == "distinct-origins" else "key-manager",
                                      key_context=device["id"] if case == "distinct" else "session")
                        digest = save(base / relative, {"stdout": json.dumps(record)})
                        observations.append(dict(kind="public-key-context", device_id=device["id"], returncode=0,
                                                 raw_path=relative, raw_sha256="" if case == "corrupt" else digest))
                    save(base / "snapshot.json", dict(devices=devices, observations=observations))
                    if case in {"missing", "corrupt", "inactive"}:
                        with self.assertRaises(ValueError):
                            check_key_contexts(base, {"devices":devices}, base / case)
                    else:
                        result = check_key_contexts(base, {"devices":devices}, base / case)
                        self.assertEqual(result["status"], "rejected" if case == "shared" else "pass", result["errors"])
                        if case == "shared":
                            self.assertIn("active_layers_have_distinct_key_contexts", " ".join(result["failed_obligations"]))
