"""Regenerate weakened evidence in isolation and require Lean to reject it."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("msc_mutation_import", ROOT / "scripts/import_msc_snapshot.py")
IMPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORTER)


class LeanContractMutationTests(unittest.TestCase):
    def test_required_proofs_survive_optional_management_variants(self):
        lake = shutil.which("lake") or str(Path.home() / ".elan/bin/lake")
        with tempfile.TemporaryDirectory(prefix="tdn-optional-management-") as temporary:
            work = Path(temporary)
            shutil.copytree(ROOT / "TDN", work / "TDN")
            for name in ["TDN.lean", "Main.lean", "lakefile.toml", "lean-toolchain"]:
                shutil.copy2(ROOT / name, work / name)
            env = dict(os.environ)
            env.pop("LEAN_PATH", None)
            for mode in ["unavailable", "absent", "firewall-drift", "missing-status",
                         "inconsistent-subnets", "corrupt-optional-files", "missing-probes"]:
                with self.subTest(mode=mode):
                    snapshot = work / mode
                    shutil.copytree(IMPORTER.CURRENT_EVIDENCE / "snapshot", snapshot)
                    spec = json.loads((snapshot / "spec.json").read_text())
                    status = json.loads((snapshot / "status.json").read_text())
                    manifest = json.loads((snapshot / "manifest.json").read_text())
                    checks = json.loads((IMPORTER.CURRENT_EVIDENCE / "check.json").read_text())
                    excluded = {d["id"] for d in spec["devices"] if d["role"] == "admin" or
                                all(i["zone"] == "management" for i in d["interfaces"])}
                    if mode == "absent":
                        zones = {(d["id"], i["name"]): i["zone"] for d in spec["devices"] for i in d["interfaces"]}
                        spec["links"] = [l for l in spec["links"] if zones[l["a"]["device"], l["a"]["interface"]] != "management"]
                        spec["devices"] = [d for d in spec["devices"] if d["id"] not in excluded]
                        for device in spec["devices"]:
                            device["interfaces"] = [i for i in device["interfaces"] if i["zone"] != "management"]
                            device.pop("admin", None)
                        status["devices"] = [d for d in status["devices"] if d["device"] not in excluded]
                    elif mode == "unavailable":
                        for device in status["devices"]:
                            if device["device"] in excluded:
                                device["state"] = "stopped"
                                device["errors"] = {"status": "optional management plane unavailable"}
                                device["facts"] = {}
                                device.pop("deployed_spec_sha256", None)
                        for relative in list(manifest["sha256"]):
                            if relative.startswith("devices/") and relative.split("/")[1] in excluded:
                                (snapshot / relative).unlink()
                                del manifest["sha256"][relative]
                    elif mode == "missing-status":
                        status["devices"] = [d for d in status["devices"] if d["device"] not in excluded]
                    elif mode == "inconsistent-subnets":
                        for device in spec["devices"]:
                            for interface in device["interfaces"]:
                                if interface["zone"] == "management" and interface.get("address"):
                                    interface["address"] = "invalid optional management address"
                    elif mode in {"firewall-drift", "corrupt-optional-files"}:
                        for device in excluded:
                            relative = f"devices/{device}/observed.iptables"
                            path = snapshot / relative
                            path.write_text("unsupported optional firewall configuration")
                            if mode == "firewall-drift":
                                manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                    for check in checks["checks"]:
                        if set(check["name"].split("/")) & excluded:
                            check["passed"] = False
                    checks["passed"] = False
                    digest = hashlib.sha256(json.dumps(spec, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                    status["spec_sha256"] = checks["spec_sha256"] = digest
                    for device in status["devices"]:
                        if "deployed_spec_sha256" in device:
                            device["deployed_spec_sha256"] = digest
                    manifest["spec_sha256"] = digest
                    for name, value in [("spec.json", spec), ("status.json", status)]:
                        path = snapshot / name
                        path.write_text(json.dumps(value))
                        manifest["sha256"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
                    (snapshot / "manifest.json").write_text(json.dumps(manifest))
                    check_path = work / "checks.json"
                    check_path.write_text(json.dumps(checks))
                    if mode == "missing-probes":
                        check_path.unlink()
                    (work / "TDN/MSC/Deployment.lean").write_text(IMPORTER.translate(snapshot, check_path))
                    result = subprocess.run([lake, "build", "TDN"], cwd=work, env=env,
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
                    self.assertEqual(result.returncode, 0, result.stdout)

    def test_regenerated_security_mutations_fail_the_relevant_proof(self):
        lake = shutil.which("lake") or str(Path.home() / ".elan/bin/lake")
        mutations = [
            ("black-bypass", None, None, None, None, "outer_firewall_cut_edges"),
            ("duplicate-gray-address", None, None, None, None, "gray_addresses_unique"),
            ("selector-widen", None, None, None, None, "inner_selectors_match_red_prefixes"),
            ("selector-narrow", None, None, None, None, "inner_selectors_match_red_prefixes"),
            ("substituted-ca", None, None, None, None, "sampled_certificates_match_ca_metadata"),
            ("duplicated-ca-key-id", None, None, None, None, "sampled_distinct_trust_ca_identifiers"),
            ("duplicated-local-key-id", None, None, None, None, "sampled_local_certificate_identifiers_unique"),
            ("missing-certificates", None, None, None, None, "sampled_credentials_complete"),
            ("wrong-peer-certificate", None, None, None, None, "sampled_credentials_match_identities"),
            ("wrong-policy-id", "I_A1", "iptables", "--reqid 101", "--reqid 999", "contract_lookup_matches"),
            ("wrong-policy-direction", "I_A1", "iptables", "--dir out", "--dir in", "contract_lookup_matches"),
            ("unrestricted-inner-protocol", "I_A1", "iptables", "-p tcp ", "", "contract_lookup_matches"),
            ("missing-outer-header-guard", "O_A1", "iptables", "--u32", "", "contract_lookup_matches"),
            ("broad-outer-allow", "O_A1", "iptables", "COMMIT", "-A FORWARD -m policy --dir out --pol ipsec --reqid 201 --mode tunnel -j ACCEPT\nCOMMIT", "contract_lookup_matches"),
            ("open-outer-firewall", "OF_B2", "iptables", "COMMIT", "-A FORWARD -j ACCEPT\nCOMMIT", "contract_lookup_matches"),
            ("missing-ike-allow", "OF_B2", "iptables", "--dports 500,4500", "--dports 4500", "contract_lookup_matches"),
            ("wrong-ike-version", "I_A1", "swanctl.conf", "version = 2", "version = 1", "intended_ikev2_tunnel_mode"),
            ("wrong-esp-mode", "I_A1", "swanctl.conf", "mode = tunnel", "mode = transport", "intended_ikev2_tunnel_mode"),
            ("wrong-gcm-proposal", "I_A1", "swanctl.conf", "esp_proposals = aes256gcm16-ecp384", "esp_proposals = aes128gcm16-ecp384", "intended_gcm_proposals"),
            ("excess-ike-lifetime", "I_A1", "swanctl.conf", "over_time = 10m", "over_time = 24h", "intended_ike_lifetime_bound"),
            ("excess-child-lifetime", "I_A1", "swanctl.conf", "life_time = 1h", "life_time = 9h", "intended_child_lifetime_bound"),
            ("weaken-authentication", "I_A1", "swanctl.conf", "auth = pubkey", "auth = psk", "intended_certificate_authentication"),
            ("wildcard-peer-identity", "I_A1", "swanctl.conf", "id = I_B1.msc.test", "id = %any", "intended_peer_identities"),
            ("wrong-local-identity", "I_A1", "swanctl.conf", "id = I_A1.msc.test", "id = unrelated.msc.test", "intended_peer_identities"),
            ("relaxed-revocation", "I_A1", "swanctl.conf", "revocation = strict", "revocation = relaxed", "intended_strict_revocation"),
        ]
        with tempfile.TemporaryDirectory(prefix="tdn-proof-mutations-") as temporary:
            work = Path(temporary)
            shutil.copytree(ROOT / "TDN", work / "TDN")
            for name in ["TDN.lean", "Main.lean", "lakefile.toml", "lean-toolchain"]:
                shutil.copy2(ROOT / name, work / name)
            env = dict(os.environ)
            env.pop("LEAN_PATH", None)
            for name, device, suffix, old, new, theorem in mutations:
                with self.subTest(mutation=name):
                    snapshot = work / "snapshot"
                    if snapshot.exists():
                        shutil.rmtree(snapshot)
                    shutil.copytree(IMPORTER.CURRENT_EVIDENCE / "snapshot", snapshot)
                    manifest_path = snapshot / "manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    checks_path = IMPORTER.CURRENT_EVIDENCE / "check.json"
                    if name in {"black-bypass", "duplicate-gray-address", "selector-widen", "selector-narrow"}:
                        spec = json.loads((snapshot / "spec.json").read_text())
                        status = json.loads((snapshot / "status.json").read_text())
                        if name == "black-bypass":
                            black = next(d for d in spec["devices"] if d["id"] == "BLACK")
                            port = next(p["name"] for p in black["interfaces"] if p["zone"] == "black")
                            spec["links"].append({"a": {"device": "O_A1", "interface": "black"}, "b": {"device": "BLACK", "interface": port}})
                        elif name == "duplicate-gray-address":
                            outer = next(d for d in spec["devices"] if d["id"] == "O_A2")
                            next(p for p in outer["interfaces"] if p["zone"] == "gray")["address"] = "10.100.1.2/24"
                        else:
                            changes = {"10.1.1.0/24": "10.1.0.0/16", "10.2.1.0/24": "10.2.0.0/16"}
                            if name == "selector-narrow":
                                changes = {old: old.replace("/24", "/25") for old in changes}

                            def altered(text):
                                for before, after in changes.items():
                                    text = text.replace(before, after)
                                return text

                            for declared in spec["devices"]:
                                if declared["id"] in {"I_A1", "I_B1"}:
                                    for field in ["local_ts", "remote_ts"]:
                                        declared["tunnel"][field] = altered(declared["tunnel"][field])
                            for observed in status["devices"]:
                                if observed["device"] in {"I_A1", "I_B1"}:
                                    observed["facts"] = {key: altered(value) for key, value in observed["facts"].items()}
                            for owner in ["I_A1", "I_B1"]:
                                for suffix_name in ["intended.iptables", "observed.iptables", "intended.swanctl.conf"]:
                                    relative = f"devices/{owner}/{suffix_name}"
                                    path = snapshot / relative
                                    path.write_text(altered(path.read_text()))
                                    manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                        digest = hashlib.sha256(json.dumps(spec, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                        status["spec_sha256"] = digest
                        for device_status in status["devices"]:
                            device_status["deployed_spec_sha256"] = digest
                        manifest["spec_sha256"] = digest
                        for relative, value in [("spec.json", spec), ("status.json", status)]:
                            path = snapshot / relative
                            path.write_text(json.dumps(value))
                            manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                        report = json.loads(checks_path.read_text())
                        report["spec_sha256"] = digest
                        checks_path = work / "check.json"
                        checks_path.write_text(json.dumps(report))
                    if name in {"substituted-ca", "duplicated-ca-key-id", "duplicated-local-key-id", "missing-certificates", "wrong-peer-certificate"}:
                        status = json.loads((snapshot / "status.json").read_text())
                        facts = {d["device"]: d["facts"] for d in status["devices"]}
                        donor = facts["I_A1"]["certificates"]
                        target = facts["I_A2"]["certificates"]
                        if name == "missing-certificates":
                            del facts["I_A2"]["certificates"]
                        else:
                            donor_ca = donor.split("List of X.509 CA Certificates")[1].split("List of X.509 CRLs")[0]
                            target_ca = target.split("List of X.509 CA Certificates")[1].split("List of X.509 CRLs")[0]
                            if name == "substituted-ca":
                                target = target.replace(target_ca, donor_ca)
                            elif name == "duplicated-ca-key-id":
                                before = re.search(r"  keyid:\s*(\S+)", target_ca)[1]
                                after = re.search(r"  keyid:\s*(\S+)", donor_ca)[1]
                                target = target.replace(before, after)
                            elif name == "duplicated-local-key-id":
                                before = re.search(r"  keyid:\s*(\S+)", target)[1]
                                after = re.search(r"  keyid:\s*(\S+)", donor)[1]
                                target = target.replace(before, after)
                            else:
                                target = target.replace("I_B2.msc.test", "unrelated.msc.test")
                            facts["I_A2"]["certificates"] = target
                        path = snapshot / "status.json"
                        path.write_text(json.dumps(status))
                        manifest["sha256"]["status.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    kinds = [] if suffix is None else (["intended", "observed"] if suffix == "iptables" else ["intended"])
                    for kind in kinds:
                        relative = f"devices/{device}/{kind}.{suffix}"
                        path = snapshot / relative
                        text = path.read_text()
                        self.assertIn(old, text)
                        if name == "missing-outer-header-guard":
                            text = re.sub(r' -m u32 --u32 "[^"]+"', '', text)
                        else:
                            text = text.replace(old, new)
                        path.write_text(text)
                        manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                    manifest_path.write_text(json.dumps(manifest))
                    generated = IMPORTER.translate(snapshot, checks_path)
                    (work / "TDN/MSC/Deployment.lean").write_text(generated)
                    result = subprocess.run([lake, "build", "TDN"], cwd=work, env=env,
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
                    self.assertNotEqual(result.returncode, 0, name + " unexpectedly passed")
                    spans = []
                    for path in (work / "TDN/MSC").glob("*.lean"):
                        text = path.read_text()
                        start = re.search(rf"(?m)^theorem {theorem}\b", text)
                        if start:
                            following = re.search(r"(?m)^(?:theorem |end )", text[start.end():])
                            end = start.end() + following.start() if following else len(text)
                            spans.append((path.stem, text[:start.start()].count("\n") + 1, text[:end].count("\n") + 1))
                    errors = re.findall(r"error: TDN/MSC/(\w+)\.lean:(\d+):", result.stdout)
                    self.assertTrue(any(module == file and low <= int(line) <= high
                                        for module, line in errors for file, low, high in spans), result.stdout)


if __name__ == "__main__":
    unittest.main()
