"""Preserve key-derived digest behavior and the complete exposed API inventory."""

import ast
import hashlib
import json
from pathlib import Path
import re

from . import key_token
from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "token_api", "observations", "coverage"]
LEAN_VIEW = "token_api_extensions"
SCOPE = "Observed private-derived operations and v2.40/v3.0 interfaces; exhaustive implementation correspondence remains explicit"
SOURCE_HASHES = {
    "token_extra_lab.py": "e4756beaa40b184f6b5c8f8000bb4460623e87c4a4d27002981f2b2a19184795",
    "token_extra_operations.py": "1baf450785fb83601c2b11753dd796dd1c6e0331ed334a9c3f9b981fc34c46cd",
}


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    _, base = key_token.parse(root / "base")
    context = json.loads((root / "context.json").read_text())
    require(context["baseManifestSha256"] == base["manifestSha256"], "Token follow-up base differs")
    validate_files(root / "extra")
    for name, expected in SOURCE_HASHES.items():
        require(hashlib.sha256((root / "extra" / name).read_bytes()).hexdigest() == expected,
                "Unreviewed token follow-up collector")
    syntax = ast.parse((root / "extra/token_extra_operations.py").read_text())
    inventories = {node.targets[0].id: ["C_" + name for name in ast.literal_eval(node.value.func.value).split()]
                   for node in syntax.body if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id in ["FUNCTIONS", "FUNCTIONS_3"]}
    document = json.loads((root / "extra/observations.json").read_text())
    require(document["phase"] == "extra-api" and document["error"] is None, "Token follow-up failed")
    rows = document["records"]
    require(len(rows) == 9 and len({row["id"] for row in rows}) == 9 and
            all(row["returncode"] == 0 for row in rows), "Incomplete token follow-up observations")
    nm = key_token.one(rows, lambda row: row["command"][:3] == ["nm", "-D", "--defined-only"],
                       "Missing token dynamic-symbol inventory")
    symbols = [line.split()[-1] for line in nm["stdout"].splitlines() if line.strip()]
    require(set(symbols) == {"C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList"},
            "Unexpected token client dynamic interface")
    binary_hash_row = key_token.one(rows, lambda row: row["command"][0] == "sha256sum", "Missing copied client hash")
    binary_hash = binary_hash_row["stdout"].split()[0]
    require(nm["command"][-1] == binary_hash_row["command"][-1], "Dynamic symbols refer to a different binary")
    results = []
    for original in base["token_keys"]:
        gateway = original["device"]
        command = ["docker", "exec", gateway, "python3", "/lab/token_extra_operations.py", "--module",
                   key_token.CLIENT_MODULE, "--credentials", "/credentials/pin.json"]
        observation = key_token.one(rows, lambda row: row["command"] == command, "Missing token API observation")
        value = json.loads(observation["stdout"])
        for field in ["publicSPKISha256", "certificateSha256", "label", "keyIdHex"]:
            require(value[field] == original["exercise"][field], "Token follow-up key/certificate identity differs")
        require(value["signatureVerified"] is True and len(bytes.fromhex(value["signatureHex"])) == 96,
                "Follow-up signing correspondence failed")
        codes = {"digestKeyCode": 0, "digestFinalCode": 0, "operationStateCode": 84, "deriveCode": 104, "decryptInitCode": 104}
        require(all(value[field] == code for field, code in codes.items()), "Unexpected additional API outcome")
        require(value["digestBytes"] == 48 and value["digestBytesExported"] is False and
                value["operationStateBytesExported"] is False and
                re.fullmatch(r"[a-f0-9]{64}", value["digestReferenceSha256"]), "Invalid opaque digest record")
        expected_calls = {"C_DigestInit": 0, "C_DigestKey": 0, "C_DigestFinal": 0,
                          "C_GetOperationState": 84, "C_DeriveKey": 104, "C_DecryptInit": 104}
        for operation, code in expected_calls.items():
            call = key_token.one(value["operations"], lambda row: row["operation"] == operation, "Missing API call")
            require(call["returnCode"] == code, "API summary and actual return code differ")
        api = value["api"]
        require(api["functionListVersion"] == [2, 40] and api["cryptokiVersion"] == [3, 0], "Unknown token API version")
        require(set(api["directSymbols"]) == set(symbols) and all(api["directSymbols"].values()), "Symbol inventory differs")
        require(len(api["callableFunctions"]) == len(set(api["callableFunctions"])) == 68, "Incomplete legacy function inventory")
        require(api["callableFunctions"] == inventories["FUNCTIONS"], "Legacy function list differs from the inspected table")
        require(len(api["interfaces"]) == 2, "Unexpected token interface count")
        for version, count in [([2, 40], 68), ([3, 0], 92)]:
            interface = key_token.one(api["interfaces"], lambda row: row["version"] == version, "Missing exposed interface")
            require(interface["knownLayout"] is True and interface["name"] == "PKCS 11" and interface["flags"] == 0,
                    "Unknown token interface layout")
            require(len(interface["callableFunctions"]) == len(set(interface["callableFunctions"])) == count and
                    set(api["callableFunctions"]).issubset(interface["callableFunctions"]), "Incomplete interface function inventory")
            expected_functions = inventories["FUNCTIONS"] + (inventories["FUNCTIONS_3"] if version == [3, 0] else [])
            require(interface["callableFunctions"] == expected_functions, "Exposed interface table differs")
        hashes_row = key_token.one(rows, lambda row: row["command"] == ["docker", "exec", gateway, "sha256sum",
                                  key_token.CLIENT_MODULE, "/etc/swanctl/x509/cert.pem", "/lab/token_extra_operations.py"],
                                  "Missing follow-up binary/credential hashes")
        hashes = {line.split(maxsplit=1)[1].strip(): line.split()[0] for line in hashes_row["stdout"].splitlines()}
        require(hashes[key_token.CLIENT_MODULE] == binary_hash and
                hashes["/etc/swanctl/x509/cert.pem"] == value["certificateSha256"] and
                hashes["/lab/token_extra_operations.py"] == SOURCE_HASHES["token_extra_operations.py"],
                "Follow-up binary/credential hash differs")
        original_hash = key_token.one(base["observations"], lambda row: row["record"]["command"] ==
                                     ["docker", "exec", gateway, "sha256sum", key_token.CLIENT_MODULE,
                                      "/usr/lib/ipsec/plugins/libstrongswan-pkcs11.so"], "Missing original client hash")
        require(original_hash["record"]["stdout"].split()[0] == binary_hash, "Client binary changed between captures")
        results.append({"device": gateway, "record": value, "dynamicSymbols": symbols,
                        "clientModuleSha256": binary_hash, "observation": "extra:" + observation["id"]})
    observations = [{**row, "id": "base:" + row["id"]} for row in base["observations"]]
    observations += [{"id": "extra:" + row["id"], "record": row} for row in rows]
    report = {"devices": base["devices"], "token_api": results, "observations": observations,
              "coverage": base["coverage"] + [{"scope": text} for text in context["scope"]],
              "manifestSha256": manifest_hash, "baseManifestSha256": base["manifestSha256"],
              "scope": [SCOPE], "projectionVersion": "pkcs11-token-extra-v1"}
    return {"runtime_backend": "native-Linux-PKCS11-RPC"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    row = key_token.one(report["observations"], lambda row: row["id"] == observation, "Unknown additional token observation")
    return row["record"]["stderr" if stderr else "stdout"]


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
