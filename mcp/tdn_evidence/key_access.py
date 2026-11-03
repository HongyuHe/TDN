"""Expose actual daemon, key and administration-interface audit observations."""

import ast
import hashlib
import json
from pathlib import Path
import re

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "key_access", "observations", "coverage"]
LEAN_VIEW = "key_access_boundary"
SCOPE = "Public daemon/key/interface metadata; no universal no-export guarantee"
SOURCE_SHA256 = "63cb919c81212a25ec711ba57c1caae812e3b52f3f0dada12d77a8edda23e4af"


def one(rows, predicate, message):
    matches = [row for row in rows if predicate(row)]
    require(len(matches) == 1, message)
    return matches[0]


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    source = (root / "collector.py").read_bytes()
    require(hashlib.sha256(source).hexdigest() == SOURCE_SHA256, "Unreviewed key-audit collector")
    syntax = ast.parse(source)
    observers = {node.targets[0].id: ast.literal_eval(node.value) for node in syntax.body
                 if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                 and node.targets[0].id in ["PROCESS_OBSERVER", "PUBLIC_KEY_OBSERVER"]}
    document = json.loads((root / "observations.json").read_text())
    rows = document["records"]
    require(len({row["id"] for row in rows}) == len(rows), "Duplicate key-audit observation")
    require(len(document["devices"]) == len(set(document["devices"])) > 0, "Invalid key-audit device inventory")
    results = []
    for device in document["devices"]:
        def item(kind, arguments=None):
            row = one(rows, lambda row: row["device"] == device and row["kind"] == kind,
                      "Missing or duplicate key-audit observation")
            require(row["returncode"] == 0, "Required key-audit command failed")
            if arguments is not None:
                require(row["command"] == ["docker", "exec", device] + arguments, "Key-audit command differs")
            return row
        process_row = item("daemon-process", ["python3", "-c", observers["PROCESS_OBSERVER"]])
        process_document = json.loads(process_row["stdout"])
        require(process_document["lookup"]["returncode"] == 0 and len(process_document["processes"]) == 1,
                "Actual charon process is absent or ambiguous")
        process = process_document["processes"][0]
        require(process["pid"] > 0 and process["executable"].endswith("/charon"), "Invalid daemon identity")
        status_pid = re.search(r"(?m)^Pid:\s+(\d+)$", process["status"])
        require(status_pid and int(status_pid[1]) == process["pid"], "Daemon status PID differs")
        require(any(module["path"] == process["executable"] for module in process["modules"]), "Daemon binary hash missing")
        for module in process["modules"]:
            require("error" not in module and re.fullmatch(r"[a-f0-9]{64}", module["sha256"]) and module["bytes"] > 0,
                    "Missing daemon/module hash")
        stats = item("daemon-stats", ["swanctl", "--stats"])
        plugins = re.search(r"(?m)^loaded plugins: (.*)$", stats["stdout"])
        require(plugins is not None, "Missing server-loaded plugin inventory")
        keys_row = item("public-key-bindings", ["python3", "-c", observers["PUBLIC_KEY_OBSERVER"]])
        keys = json.loads(keys_row["stdout"])
        private = [key for key in keys if key.get("path", "").startswith("/etc/swanctl/private/")]
        certificates = [key for key in keys if key.get("path", "").startswith("/etc/swanctl/x509/")]
        require(private and certificates, "Empty key/certificate file inventory")
        for key in keys:
            require(key.get("returncode") == 0 and re.fullmatch(r"[a-f0-9]{64}", key["publicSPKISha256"]),
                    "Public-key derivation failed")
        require(all(any(cert["publicSPKISha256"] == key["publicSPKISha256"] for cert in certificates) for key in private),
                "Private-file public identity has no matching certificate")
        boundary_row = one(rows, lambda row: row["device"] is None and row["kind"] == "container-boundary:" + device,
                           "Missing container boundary")
        require(boundary_row["returncode"] == 0, "Container inspection failed")
        require(len(boundary_row["command"]) == 5 and boundary_row["command"][:3] == ["docker", "inspect", "--format"]
                and boundary_row["command"][-1] == device, "Container inspection command differs")
        boundary = json.loads(boundary_row["stdout"])
        require(boundary["Name"] == "/" + device and boundary["Running"] and boundary["Pid"] > 0, "Container identity differs")
        results.append({"device": device, "daemon": process, "loadedDaemonPlugins": plugins[1].split(),
                        "keyAndCertificateFiles": keys, "containerBoundary": boundary,
                        "observations": [row["id"] for row in rows if row["device"] == device] + [boundary_row["id"]],
                        "unavailable": [{"observation": row["id"], "kind": row["kind"], "returncode": row["returncode"]}
                                        for row in rows if row["device"] == device and row["returncode"]]})
    report = {"devices": [{"id": device} for device in document["devices"]], "key_access": results,
              "observations": [{"id": row["id"], "device": row["device"], "record": row} for row in rows],
              "coverage": [{"scope": scope} for scope in document["scope"]],
              "manifestSha256": manifest_hash, "scope": [SCOPE], "projectionVersion": "key-interface-audit-v1"}
    return {"runtime_backend": "native-Linux-container-key-audit"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    row = one(report["observations"], lambda row: row["id"] == observation, "Unknown key-audit observation")
    return row["record"]["stderr" if stderr else "stdout"]


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
