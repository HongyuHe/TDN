"""Expose retained administration observations without inventing session records."""
import ast
import hashlib
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "credentials", "permissions", "operations", "audit_events", "listeners", "coverage", "observations"]
LEAN_VIEW = "administration_observations"
SCOPE = "Historical certificate-role checks, API operations, audit records and runtime observations"


def parse(directory):
    directory = Path(directory)
    manifest_hash = validate_files(directory)
    sources = json.loads((directory / "sources.json").read_text())
    require(sources["schema"] == "administration-retained/v1", "Unsupported administration capture")
    expected = {"role-admin-deploy-v3", "role-admin-deploy-v4", "role-admin-effective-v3",
                "role-admin-matrix-v3", "central-gray-management-v3"}
    require(set(sources["captures"]) == expected, "Administration source inventory differs")
    captures, observations, coverage = {}, [], []
    for name in sorted(expected):
        path = directory / name
        supplemental = []
        if name == "central-gray-management-v3":
            original = json.loads((path / "manifest.json").read_text())
            listed = {record["path"] for record in original["files"]}
            actual = {str(item.relative_to(path)) for item in path.rglob("*")
                      if item.is_file() and item != path / "manifest.json"}
            require(len(listed) == len(original["files"]) and actual - listed == {"ca-public/ca.pem"} and
                    not listed - actual, "Unexpected historical supplemental files")
            for record in original["files"]:
                target = (path / record["path"]).resolve()
                target.relative_to(path.resolve())
                require(hashlib.sha256(target.read_bytes()).hexdigest() == record["sha256"],
                        "Historical public file hash mismatch")
            supplemental = ["ca-public/ca.pem"]
        else:
            validate_files(path)
        record_file = path / "observations.json"
        if record_file.exists():
            capture = json.loads(record_file.read_text())
            rows = capture["records"]
            error = capture.get("error")
        else:
            rows = json.loads((path / "commands.json").read_text())
            error = json.loads((path / "evidence.json").read_text()).get("error")
        captures[name] = rows
        coverage.append({"source": name, "captureError": error, "observations": len(rows),
                         "filesCoveredOnlyByAggregateManifest": supplemental,
                         "scope": "Raw capture retained, including failed deployment attempts."})
        observations.extend({"id": name + "-record-" + str(index), "source": name,
            "sourceIndex": index, "record": row} for index, row in enumerate(rows))
    deployment = directory / "role-admin-deploy-v4"
    roles = json.loads((deployment / "role-map.json").read_text())
    permissions = json.loads((deployment / "permissions.json").read_text())
    service_bytes = (deployment / "service.py").read_bytes()
    service_hash = hashlib.sha256(service_bytes).hexdigest()
    tree = ast.parse(service_bytes)
    assigned = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
                for target in node.targets if isinstance(target, ast.Name)}
    parsed_permissions = ast.literal_eval(assigned["permissions"])
    require(parsed_permissions == {key: value for key, value in permissions.items() if key != "all_roles"},
            "Permission records differ from the service source")
    credentials = []
    for principal in ["security-admin", "auditor", "unmapped"]:
        path = deployment / (principal + ".public.pem")
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest()
        credentials.append({"configuredPrincipal": principal, "certificateSha256": digest,
            "role": roles.get(digest, "Unmapped"), "source": str(path.relative_to(directory)),
            "identityScope": "Configured test credential name; no real person or organizational appointment is inferred."})
    require(set(roles) == {record["certificateSha256"] for record in credentials if record["role"] != "Unmapped"},
            "Role map refers to an uncollected certificate")
    effective = captures["role-admin-effective-v3"]
    require(all(row["returncode"] == 0 for row in effective), "Effective administration collection failed")
    require(any(row["stdout"].strip() == service_hash and row["command"][:3] == ["docker", "exec", "ND_O_A1"]
                for row in effective), "Runtime service hash differs from the retained source")
    require(any(row["command"] == ["docker", "exec", "ND_O_A1", "cat", "/root/role-admin-v4/role-map.json"] and
                json.loads(row["stdout"]) == roles for row in effective), "Runtime role map differs")
    listeners = []
    for index, row in enumerate(effective):
        if row["command"] == ["docker", "exec", "ND_O_A1", "ss", "-lntp"]:
            require("172.28.96.2:8443" in row["stdout"], "Configured administration listener was not observed")
            listeners.append({"device": "ND_O_A1", "address": "172.28.96.2", "port": 8443,
                "transport": "tcp", "service": "certificate-authenticated administration API",
                "observation": "role-admin-effective-v3-record-" + str(index), "raw": row["stdout"],
                "serviceSha256": service_hash})
    require(bool(listeners), "Missing runtime listener record")
    matrix = captures["role-admin-matrix-v3"]
    operations = []
    by_principal = {record["configuredPrincipal"]: record for record in credentials}
    for index, row in enumerate(matrix):
        if row.get("probe") != "role-operation":
            continue
        argv = row["command"]
        principal = by_principal[row["principal"]]
        method = "HEAD" if "--head" in argv else argv[argv.index("-X") + 1]
        endpoint = urlsplit(next(value for value in argv if value.startswith("https://")))
        status = re.findall(r"HTTP_STATUS=(\d{3})", row["stdout"])
        require(row["returncode"] == 0 and method == row["method"] and endpoint.path == row["path"] and
                endpoint.hostname == "managed.nd.test" and endpoint.port == 8443 and
                "managed.nd.test:8443:172.28.96.2" in argv and
                Path(argv[argv.index("--cert") + 1]).name == row["principal"] + ".pem" and
                len(status) == 1 and int(status[0]) == row["observed_result"], "Unbound administration operation")
        allowed = row["path"] in parsed_permissions.get(principal["role"], {}).get(method, [])
        require(row["observed_result"] == (200 if allowed else 403), "Observed API outcome differs from its permission rule")
        operations.append({"device": "ND_O_A1", "configuredPrincipal": row["principal"],
            "certificateSha256": principal["certificateSha256"], "role": principal["role"],
            "method": method, "path": endpoint.path, "status": int(status[0]),
            "destinationAddress": "172.28.96.2", "destinationPort": 8443,
            "sourcePort": None, "sessionId": None, "operationToken": None,
            "observation": "role-admin-matrix-v3-record-" + str(index)})
    require(len(operations) == 21, "Incomplete three-principal operation matrix")
    audit = []
    for index, row in enumerate(effective):
        argv = row["command"]
        if len(argv) == 5 and argv[:4] == ["docker", "exec", "ND_O_A1", "cat"] and "/audit" in argv[4]:
            for line, text in enumerate(row["stdout"].splitlines(), 1):
                event = json.loads(text)
                require(event["role"] == roles.get(event["fingerprint"], "Unmapped"), "Audit role differs from its credential")
                audit.append(event | {"device": "ND_O_A1", "observation": "role-admin-effective-v3-record-" + str(index),
                                      "line": line})
    require(bool(audit), "Missing runtime audit records")
    for operation in operations:
        require(any(event["fingerprint"] == operation["certificateSha256"] and
                    all(event[key] == operation[key] for key in ["role", "method", "path", "status"])
                    for event in audit), "Operation has no corresponding runtime audit record")
    central = directory / "central-gray-management-v3"
    for name in ["OB", "CA"]:
        code = (central / (name + "-service.py")).read_text()
        calls = [node for node in ast.walk(ast.parse(code)) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Attribute) and node.func.attr == "HTTPServer"]
        require(len(calls) == 1, "Expected one captured HTTP service listener")
        address, port = ast.literal_eval(calls[0].args[0])
        listeners.append({"device": name, "address": address, "port": port, "transport": "tcp",
            "service": "HTTP file service", "clientCertificateRequired": "CERT_REQUIRED" in code,
            "source": "central-gray-management-v3/" + name + "-service.py",
            "evidenceKind": "Captured service source; inspect raw commands for interface ownership and runtime bindings."})
    coverage.append({"source": "combined", "missing": ["Complete operating-system account and AW administrator inventories",
        "Account creation order", "Explicit application session IDs and operation tokens", "Logout and credential-revocation events",
        "A packet capture giving every client source port", "Organizational CNSA/NIST assurance and human role appointments"],
        "authenticationModel": "The retained API authenticates the client certificate on each TLS connection. It implements no application login/session-token/logout API."})
    report = {"devices": [{"id": name} for name in ["ND_O_A1", "OB", "CA"]],
        "credentials": credentials, "permissions": [{"device": "ND_O_A1", "roles": parsed_permissions,
            "serviceSha256": service_hash}], "operations": operations, "audit_events": audit,
        "listeners": listeners, "coverage": coverage, "observations": observations,
        "rawObservationIds": [row["id"] for row in observations], "manifestSha256": manifest_hash,
        "projectionVersion": "administration-observations-v1", "scope": [SCOPE,
            "Captured runtime source, role map, operations and audit are checked. Missing session/account fields remain explicit.",
            "TLS implementation, collector truth and host control remain assumptions. Optional administration does not become a core packet-safety prerequisite."]}
    return {"runtime_backend": "retained-mtls-administration"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    matches = [row for row in report["observations"] if row["id"] == observation]
    require(len(matches) == 1, "Unknown administration observation")
    return matches[0]["record"].get("stderr" if stderr else "stdout", "")


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
