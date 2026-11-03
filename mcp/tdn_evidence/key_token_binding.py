"""Bind the legacy backend and newer client interface to observed modules."""

import hashlib
import json
from pathlib import Path

from . import key_token, key_token_extra
from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "token_interfaces", "observations", "coverage"]
LEAN_VIEW = "token_interface_binding"
SCOPE = "Actual backend version and valid-session client v3 rejection; exhaustive implementation correspondence remains explicit"
SOURCE_HASHES = {
    "token_interface_binding.py": "9db0a6d3ac75bc3778d9a67d937c3da4f5ac60450f2ce6e553d264e621b79129",
    "token_interface_lab.py": "de183eef95bfa073e5c56e1525a04214f26510004c1aaefdc2a34aee163f643e",
    "token_extra_operations.py": key_token_extra.SOURCE_HASHES["token_extra_operations.py"],
}
BACKEND_MODULE = "/usr/lib/softhsm/libsofthsm2.so"


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    _, prior = key_token_extra.parse(root / "prior")
    context = json.loads((root / "context.json").read_text())
    require(context["priorManifestSha256"] == prior["manifestSha256"], "Interface binding prior differs")
    validate_files(root / "binding")
    for name, expected in SOURCE_HASHES.items():
        require(hashlib.sha256((root / "binding" / name).read_bytes()).hexdigest() == expected,
                "Unreviewed interface-binding collector")
    document = json.loads((root / "binding/observations.json").read_text())
    require(document["phase"] == "interface-binding" and document["error"] is None, "Interface-binding capture failed")
    rows = document["records"]
    require(len(rows) == len({row["id"] for row in rows}) == 12 and all(row["returncode"] == 0 for row in rows),
            "Incomplete interface-binding capture")
    results = []
    for original in prior["token_api"]:
        gateway = original["device"]
        backend = gateway.replace("_G_", "_T_")
        values = {}
        references = []
        for device, module in [(backend, BACKEND_MODULE), (gateway, key_token.CLIENT_MODULE)]:
            command = ["docker", "exec", device, "python3", "/lab/token_interface_binding.py", "--module", module]
            if device == gateway:
                command += ["--credentials", "/credentials/pin.json"]
            row = key_token.one(rows, lambda row: row["command"] == command, "Missing version-binding observation")
            value = json.loads(row["stdout"])
            require(value["module"] == module and value["legacyFunctionListVersion"] == [2, 40],
                    "Unexpected actual module version")
            values[device] = value
            references.append("binding:" + row["id"])
        server, client = values[backend], values[gateway]
        require(server["selectedFunctionListVersion"] == server["cryptokiVersion"] == [2, 40] and
                server["libraryVersion"] == [2, 6], "Backend does not expose the recorded legacy interface")
        old_hash = key_token.one(prior["observations"], lambda row: row["record"]["command"] ==
                                ["docker", "exec", backend, "sha256sum", BACKEND_MODULE], "Missing original backend hash")
        require(server["moduleSha256"] == old_hash["record"]["stdout"].split()[0], "Backend binary changed")
        require(client["selectedFunctionListVersion"] == client["cryptokiVersion"] == [3, 0],
                "New client interface was not selected")
        require(client["moduleSha256"] == original["clientModuleSha256"], "Client binary changed")
        for field in ["publicSPKISha256", "certificateSha256", "label", "keyIdHex"]:
            require(client[field] == original["record"][field], "Interface test used a different key")
        require(client["signatureVerified"] is True and len(bytes.fromhex(client["signatureHex"])) == 96,
                "Valid-session signing binding failed")
        require(client["messageSignInitCode"] == 84, "New interface did not return unsupported")
        call = key_token.one(client["operations"], lambda row: row["operation"] == "C_MessageSignInit", "Missing v3 call")
        require(call["returnCode"] == 84 and all(row["returnCode"] == 0 for row in client["operations"]
                                               if row["operation"] != "C_MessageSignInit"),
                "V3 rejection occurred without successful session/key setup")
        results.append({"device": gateway, "backend": backend, "backendInterface": server,
                        "clientInterface": client, "observations": references})
    observations = [{**row, "id": "prior:" + row["id"]} for row in prior["observations"]]
    observations += [{"id": "binding:" + row["id"], "record": row} for row in rows]
    report = {"devices": prior["devices"], "token_interfaces": results, "observations": observations,
              "coverage": prior["coverage"] + [{"scope": text} for text in context["scope"]],
              "manifestSha256": manifest_hash, "priorManifestSha256": prior["manifestSha256"],
              "scope": [SCOPE], "projectionVersion": "pkcs11-token-binding-v1"}
    return {"runtime_backend": "native-Linux-PKCS11-RPC"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    row = key_token.one(report["observations"], lambda row: row["id"] == observation, "Unknown interface-binding observation")
    return row["record"]["stderr" if stderr else "stdout"]


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
