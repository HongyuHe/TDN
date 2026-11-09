"""Import the exact certificate-bound permission table of the recorded administration API."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit

AUDITED_SOURCE_SHA256 = "e258535abe2a9490be635dd6da45f8f497d01badead319ffa7be88e76f916948"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_public_bundle(path):
    path = Path(path)
    manifest = json.loads((path / "manifest.json").read_text())
    names = []
    for item in manifest["files"]:
        file = (path / item["path"]).resolve()
        file.relative_to(path.resolve())
        require(file.is_file(), "Missing public bundle file")
        require(hashlib.sha256(file.read_bytes()).hexdigest() == item["sha256"], "Bundle hash mismatch")
        names.append(item["path"])
    require(len(set(names)) == len(names), "Duplicate manifest filename")
    actual = {str(file.relative_to(path)) for file in path.rglob("*") if file.is_file() and file.name != "manifest.json"}
    require(set(names) == actual and "observations.json" in names, "Manifest omits a public input")
    return json.loads((path / "observations.json").read_text())


def parse_authorization(deployment, effective, matrix):
    deployment = Path(deployment)
    deploy = validate_public_bundle(deployment)
    runtime = validate_public_bundle(effective)
    probes = validate_public_bundle(matrix)
    require(deploy.get("error") is None and runtime.get("error") is None and probes.get("error") is None,
            "Collection failure")
    source = (deployment / "service.py").read_text()
    digest = hashlib.sha256(source.encode()).hexdigest()
    require(digest == AUDITED_SOURCE_SHA256, "Service source differs from reviewed implementation contract")
    tree = ast.parse(source)
    definitions = [
        node for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "permissions" for target in node.targets)
    ]
    require(len(definitions) == 1, "Ambiguous source permissions")
    permissions = ast.literal_eval(definitions[0].value)
    exported = json.loads((deployment / "permissions.json").read_text())
    require({key: value for key, value in exported.items() if key != "all_roles"} == permissions,
            "Exported permissions differ from executable source")
    roles = json.loads((deployment / "role-map.json").read_text())
    certificates = {}
    for name in ["security-admin", "auditor", "unmapped"]:
        pem = (deployment / (name + ".public.pem")).read_text()
        der = ssl.PEM_cert_to_DER_cert(pem)
        certificates[name] = hashlib.sha256(der).hexdigest()
    expected = {certificates["security-admin"]: "SecurityAdministrator",
                certificates["auditor"]: "Auditor"}
    require(roles == expected, "Unexpected or missing certificate role binding")
    require(certificates["unmapped"] not in roles, "Unmapped test certificate has a role")
    runtime_roles = []
    runtime_hashes = []
    for record in runtime["records"]:
        command = record["command"]
        require(record["returncode"] == 0, "Effective-state command failed")
        if command[-2:] == ["cat", "/root/role-admin-v4/role-map.json"]:
            runtime_roles.append(json.loads(record["stdout"]))
        if command[:5] == ["docker", "exec", "ND_O_A1", "python3", "-c"] and "service.py" in command[-1]:
            runtime_hashes.append(record["stdout"].strip())
    require(runtime_roles == [roles], "Effective role map differs from imported map")
    require(runtime_hashes == [digest], "Effective service source differs from imported source")
    observed = []
    for record in probes["records"]:
        command = record["command"]
        if command[0] != "curl" or "--cert" not in command:
            continue
        cert_path = command[command.index("--cert") + 1]
        name = Path(cert_path).stem
        require(name in certificates, "Unmapped public test credential")
        method = "HEAD" if "--head" in command else command[command.index("-X") + 1] if "-X" in command else "GET"
        urls = [value for value in command if value.startswith("https://managed.nd.test:8443/")]
        require(len(urls) == 1, "Ambiguous test request URL")
        path = urlsplit(urls[0]).path
        statuses = re.findall(r"HTTP_STATUS=(\d+)", record["stdout"])
        require(record["returncode"] == 0 and len(statuses) == 1, "Missing actual HTTP result")
        status = int(statuses[0])
        role = roles.get(certificates[name])
        authorized = role is not None and path in permissions.get(role, {}).get(method, [])
        require(status == (200 if authorized else 403), "Observed result disagrees with actual permission table")
        observed.append({"fingerprint": certificates[name], "method": method, "path": path,
                         "allowed": status == 200})
    expected_operations = {("GET", "/state"), ("GET", "/audit"), ("POST", "/filter"),
                           ("POST", "/audit/rotate"), ("GET", "/private-key"),
                           ("GET", "/unknown"), ("HEAD", "/state")}
    for fingerprint in certificates.values():
        actual = {(row["method"], row["path"]) for row in observed if row["fingerprint"] == fingerprint}
        require(actual == expected_operations, "Incomplete principal/operation matrix")
    return {"permissions": permissions, "roles": roles, "certificates": certificates,
            "source_sha256": digest, "observed": observed}


def generate(data):
    quoted = json.dumps
    lines = ["import TDN.Models.RoleBasedAccessControl", "", "namespace TDN.Deployments.SnapshotServiceAuthorization",
             "", "def roles (fingerprint : String) : Option String :="]
    for fingerprint, role in sorted(data["roles"].items()):
        lines.append("  if fingerprint = " + quoted(fingerprint) + " then some " + quoted(role) + " else")
    lines.append("  none")
    entries = []
    for role, methods in data["permissions"].items():
        for method, paths in methods.items():
            entries.extend("⟨" + ", ".join(map(quoted, [role, method, path])) + "⟩" for path in paths)
    lines.extend(["", "def permissions : List AccessControl.Permission := [" + ", ".join(entries) + "]"])
    for name in ["security-admin", "auditor", "unmapped"]:
        lines.extend(["", "def " + name.replace("-", "_") + " : String := " + quoted(data["certificates"][name])])
    lines.extend([
        "", "theorem all_private_key_paths_denied (fingerprint method : String) :",
        '    AccessControl.authorize roles permissions ⟨fingerprint, method, "/private-key"⟩ = false := by',
        "  apply AccessControl.absent_path_is_denied",
        "  simp [permissions]",
        "", "theorem every_unmapped_fingerprint_denied (fingerprint method path : String)",
        "    (unmappedPeer : roles fingerprint = none) :",
        "    AccessControl.authorize roles permissions ⟨fingerprint, method, path⟩ = false :=",
        "  AccessControl.unmapped_peer_is_denied roles permissions _ unmappedPeer",
        "", "def AuditorOperation (method path : String) : Prop :=",
        '  (method = "GET" ∧ path ∈ ["/state", "/audit"]) ∨',
        '  (method = "POST" ∧ path = "/audit/rotate")',
        "", "theorem every_accepted_auditor_request_is_within_scope (request : AccessControl.Request)",
        '    (role : roles request.authenticatedFingerprint = some "Auditor")',
        "    (accepted : AccessControl.authorize roles permissions request = true) :",
        "    AuditorOperation request.method request.normalizedPath := by",
        '  apply AccessControl.role_permission_restricts_operations roles permissions request "Auditor"',
        "    role accepted AuditorOperation",
        "  simp [permissions, AuditorOperation]",
        "", "theorem auditor_filter_change_denied :",
        '    AccessControl.authorize roles permissions ⟨auditor, "POST", "/filter"⟩ = false := by decide',
        "", "theorem administrator_filter_change_permitted :",
        '    AccessControl.authorize roles permissions ⟨security_admin, "POST", "/filter"⟩ = true := by decide',
        "", "def observed : List (AccessControl.Request × Bool) := ["
    ])
    rows = []
    for row in data["observed"]:
        rows.append("  (⟨" + ", ".join(map(quoted, [row["fingerprint"], row["method"], row["path"]])) +
                    "⟩, " + str(row["allowed"]).lower() + ")")
    lines.extend([",\n".join(rows) + "]", "",
                  "theorem retained_http_results_match_model : ∀ pair ∈ observed,",
                  "    AccessControl.authorize roles permissions pair.1 = pair.2 := by decide",
                  "", "end TDN.Deployments.SnapshotServiceAuthorization", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--effective", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse_authorization(args.deployment, args.effective, args.matrix)
    Path(args.output).write_text(generate(data))
    data["bundles"] = {key: getattr(args, key) for key in ["deployment", "effective", "matrix"]}
    data["scope"] = "Certificate-bound authorization for the exact recorded ND_O_A1 administration HTTP service"
    data["implementation_contract"] = [
        "The reviewed, hash-bound Python source implements the modeled permission lookup.",
        "The authenticated fingerprint is SHA-256 of the actual TLS peer certificate DER; TLS identity validation is trusted.",
        "URL normalization and HTTP method dispatch follow the captured Python standard-library implementation.",
        "No claim covers host root, Docker, hypervisor access, other services, human role appointment, or all-product key confinement."
    ]
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"observations": len(data["observed"]), "roles": len(data["roles"]),
                      "source_sha256": data["source_sha256"]}))


if __name__ == "__main__":
    main()
