"""Import verified public authority identities and instantiate general separation proofs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(command):
    result = subprocess.run(command, capture_output=True)
    require(result.returncode == 0, "Public certificate check failed: " + " ".join(command))
    return result.stdout


def lean_level(level):
    fields = [json.dumps(level["classification"])]
    for key in ["compartments", "dissemination_controls", "other_controls"]:
        fields.append("{" + ", ".join(json.dumps(v) for v in level[key]) + "}")
    return "⟨" + ", ".join(fields) + "⟩"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--declaration", required=True)
    parser.add_argument("--output-prefix", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    bundle = Path(args.bundle)
    manifest = json.loads((bundle / "manifest.json").read_text())
    for item in manifest["files"]:
        path = bundle / item["path"]
        require(path.is_file(), "Missing public observation " + item["path"])
        require(hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], "Manifest hash mismatch")
    data = json.loads((bundle / "bindings.json").read_text())
    declarations = json.loads(Path(args.declaration).read_text())
    configs = {c["configuration_id"]: c for c in declarations["configurations"]}
    reports = []
    for config_id in sorted({d["configuration_id"] for d in data["devices"]}):
        declared = configs[config_id]
        levels = {level["id"]: level for level in declared["security_levels"]}
        devices = [d for d in data["devices"] if d["configuration_id"] == config_id]
        expected = {device for net in declared["red_networks"] for device in net["inner_device_ids"]}
        require(expected == {d["device_id"] for d in devices}, "Incomplete Inner identity inventory")
        declared_level = {device: network["security_level_id"] for network in declared["red_networks"] for device in network["inner_device_ids"]}
        owners = {}
        identities = []
        for device in devices:
            require(device["security_level"] == declared_level[device["device_id"]], "Credential level differs from declared Red attachment")
            certs = device["certificates"]
            for certificate in certs:
                pem = bundle / certificate["pem_path"]
                der = run(["/opt/homebrew/opt/openssl@3/bin/openssl", "x509", "-in", str(pem), "-outform", "DER"])
                require(hashlib.sha256(der).hexdigest() == certificate["certificate_sha256"], "Certificate digest mismatch")
                public = run(["/opt/homebrew/opt/openssl@3/bin/openssl", "x509", "-in", str(pem), "-pubkey", "-noout"])
                key = subprocess.run(["/opt/homebrew/opt/openssl@3/bin/openssl", "pkey", "-pubin", "-outform", "DER"], input=public, capture_output=True)
                require(key.returncode == 0, "SPKI conversion failed")
                require(hashlib.sha256(key.stdout).hexdigest() == certificate["public_key_spki_sha256"], "Public-key digest mismatch")
            indexed = {c["certificate_sha256"]: c for c in certs}
            roots = [indexed[fingerprint] for fingerprint in device["effective_remote_root_fingerprints"]]
            require(roots, "Empty trust inventory")
            loaded_roots = {c["certificate_sha256"] for c in certs if c["source"] == "loaded-daemon-certificate" and "CA:TRUE" in c["details"]}
            require(loaded_roots == set(device["effective_remote_root_fingerprints"]), "Additional or missing loaded trust root")
            configured_roots = {c["certificate_sha256"] for c in certs if c["source"].startswith("/etc/swanctl/x509ca/")}
            require(configured_roots == loaded_roots, "Configured and loaded roots differ")
            own = indexed[device["own_certificate_sha256"]]
            require(any(c["source"] == "loaded-daemon-certificate" and c["certificate_sha256"] == device["own_certificate_sha256"] for c in certs), "Own credential not loaded")
            issuers = []
            for root in roots:
                details = root["details"]
                require("CA:TRUE" in details, "Configured root is not a CA")
                subject = run(["/opt/homebrew/opt/openssl@3/bin/openssl", "x509", "-in", str(bundle / root["pem_path"]), "-subject", "-issuer", "-noout"]).decode().splitlines()
                require(subject[0].split("=", 1)[1] == subject[1].split("=", 1)[1], "Intermediate or cross-signed root needs explicit closure extension")
                run(["/opt/homebrew/opt/openssl@3/bin/openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile", str(bundle / root["pem_path"]), str(bundle / root["pem_path"])])
                verification = subprocess.run(["/opt/homebrew/opt/openssl@3/bin/openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile", str(bundle / root["pem_path"]), str(bundle / own["pem_path"])], capture_output=True)
                if verification.returncode == 0:
                    issuers.append(root["public_key_spki_sha256"])
                key = root["public_key_spki_sha256"]
                level = lean_level(levels[device["security_level"]])
                require(key not in owners or owners[key] == level, "Authority key shared across different full levels")
                owners[key] = level
            require(len(issuers) == 1, "Own issuer chain is missing or ambiguous")
            identities.append({"device": device["device_id"], "level": lean_level(levels[device["security_level"]]), "issuer": issuers[0], "trust": sorted({c["public_key_spki_sha256"] for c in roots})})
        namespace = "ProfileBaseline_PkiTrust" if config_id == "native-ipsec-baseline" else "ProfileShared_PkiTrust"
        output = Path(args.output_prefix + namespace + ".lean")
        lines = ["import TDN.Requirements.CrossEnclavePkiIsolationSpec", "", "namespace TDN.Deployments." + namespace, "", "set_option maxRecDepth 100000", "", "def authorityLevel (key : String) : SecurityLevel :="]
        for key, level in sorted(owners.items()):
            lines.append("  if key = " + json.dumps(key) + " then " + level + " else")
        lines.append('  ⟨"UNASSIGNED", {}, {}, {}⟩')
        lines.extend(["", "def peers : List Requirements.InnerAuthentication := ["])
        rows = []
        for item in identities:
            rows.append("  ⟨" + json.dumps(item["device"]) + ", " + item["level"] + ", .certificate " + json.dumps(item["issuer"]) + " " + json.dumps(item["trust"]) + ", {}⟩")
        lines.append(",\n".join(rows) + "]")
        lines.extend(["", "/-- Management is explicitly unselected in this data-path configuration. -/", "lemma credential_scopes : ∀ peer ∈ peers, Requirements.CredentialScoped authorityLevel authorityLevel peer := by", "  simp [peers, authorityLevel, Requirements.CredentialScoped]", "", "theorem authority_material_separation : ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → Requirements.MaterialsSeparated a b := by", "  intro a ha b hb different", "  exact Requirements.scoped_materials_separated (credential_scopes a ha) (credential_scopes b hb) different", "", "theorem no_cross_level_authentication : ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → ¬ Requirements.InnerCanAuthenticate a b := by", "  intro a ha b hb different", "  exact Requirements.scoped_inner_peers_cannot_cross_levels (credential_scopes a ha) (credential_scopes b hb) different", "", "theorem snapshot_RG012_management_free : Requirements.msc_security_level_key_and_management_separation false peers := by", "  exact Requirements.separate_authentication_and_management_of_scoped_material false peers authorityLevel authorityLevel credential_scopes (by simp) (by simp)", "", "end TDN.Deployments." + namespace, ""])
        output.write_text("\n".join(lines))
        reports.append({"configuration": config_id, "devices": len(devices), "authority_keys": len(owners), "module": str(output), "identity_bindings": identities})
    report = {"bundle": args.bundle, "manifest_sha256": hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest(), "configurations": reports, "scope": "Finite configured and loaded self-signed root/key partition with public DER/SPKI rehash and fresh OpenSSL chain checks; all cross-level peer pairs are excluded in the general admission model.", "remaining_assumptions": ["Collector truth and finite trust-store completeness", "Verified successful implementation authentication implies admission under effective roots; cryptographic signature security is not proved in Lean", "Declared full security labels describe scenarios and do not classify lab traffic", "Future changes and organizational CA approvals are outside the captured interval", "Management-device assignments are unavailable and not inferred"]}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"configurations": len(reports), "devices": sum(r["devices"] for r in reports)}))


if __name__ == "__main__":
    main()
