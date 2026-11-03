"""Expose a socket-backed PKCS11 key experiment with its tested boundaries."""

import hashlib
import json
from pathlib import Path
import re

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "token_keys", "observations", "coverage"]
LEAN_VIEW = "token_key_boundary"
SCOPE = "Actual token attributes, operations, certificate bindings and isolation; software/host refinement remains explicit"
LAB_SHA256 = "aaeb322388a3f130fd089f943656dbcb6e84923fd60bf5e49b41d8a97a93d699"
OPERATIONS_SHA256 = {
    "bootstrap": "cbb793b0a50bcb5d4d301316dc9b0d735155b082ee53dbf9ebe3a7751bc79037",
    "configure": "cbb793b0a50bcb5d4d301316dc9b0d735155b082ee53dbf9ebe3a7751bc79037",
    "observe": "915b3f6f7fb3e5e1813bf1aebabe21a62da9f5b0638fbd481d4533d102dc8ca9",
}
CURRENT_OPERATIONS_SHA256 = OPERATIONS_SHA256["observe"]
CLIENT_MODULE = "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so"
EXPECTED_RETURNS = {"read-private-value": 17, "make-extractable": 27, "make-nonsensitive": 27,
                    "copy-private-key": 27, "wrap-private-key": 106, "wrong-pin-login": 160}


def one(rows, predicate, message):
    selected = [row for row in rows if predicate(row)]
    require(len(selected) == 1, message)
    return selected[0]


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    context = json.loads((root / "context.json").read_text())
    phases = {}
    observations = []
    for phase in OPERATIONS_SHA256:
        validate_files(root / phase)
        for name, accepted in [("key_token_lab.py", {LAB_SHA256}),
                               ("token_operations.py", {OPERATIONS_SHA256[phase], CURRENT_OPERATIONS_SHA256})]:
            require(hashlib.sha256((root / phase / name).read_bytes()).hexdigest() in accepted,
                    "Unreviewed token collector")
        document = json.loads((root / phase / "observations.json").read_text())
        require(document["phase"] == phase and document["error"] is None, "Token experiment phase failed")
        rows = document["records"]
        require(len({row["id"] for row in rows}) == len(rows), "Duplicate token observation")
        phases[phase] = rows
        for row in rows:
            observations.append({"id": phase + ":" + row["id"], "phase": phase, "record": row})
    results = []
    for suffix in ["A", "B"]:
        gateway, backend = "KT31_G_" + suffix, "KT31_T_" + suffix

        def command(phase, arguments, successful=True):
            row = one(phases[phase], lambda row: row["command"] == arguments,
                      "Missing or duplicate token command")
            if successful:
                require(row["returncode"] == 0, "Required token command failed")
            return row

        generation = command("bootstrap", ["docker", "exec", gateway, "python3", "/lab/token_operations.py", "generate",
                                             "--module", CLIENT_MODULE, "--credentials", "/credentials/pin.json",
                                             "--public-output", "/credentials/public.pem"])
        generated = json.loads(generation["stdout"])
        exercise = command("observe", ["docker", "exec", gateway, "python3", "/lab/token_operations.py", "exercise",
                                         "--module", CLIENT_MODULE, "--credentials", "/credentials/pin.json"])
        tested = json.loads(exercise["stdout"])
        require(generated["generated"] and generated["label"] == tested["label"] == "KT31_" + suffix,
                "Token generation identity differs")
        require(generated["keyIdHex"] == tested["keyIdHex"] == "01", "Token object identifier differs")
        require(generated["publicSPKISha256"] == tested["publicSPKISha256"] and
                re.fullmatch(r"[0-9a-f]{64}", tested["publicSPKISha256"]), "Token public key differs")
        certificate = root / "bootstrap" / (gateway + "-cert.pem")
        require(hashlib.sha256(certificate.read_bytes()).hexdigest() == tested["certificateSha256"] and
                tested["certificateSPKIMatches"] is True, "Token certificate binding differs")
        attributes = tested["attributes"]
        for attribute in ["SENSITIVE", "ALWAYS_SENSITIVE", "NEVER_EXTRACTABLE", "SIGN", "TOKEN", "PRIVATE", "LOCAL"]:
            require(attributes["CKA_" + attribute] is True, "Required token protection attribute absent")
        for attribute in ["EXTRACTABLE", "COPYABLE", "MODIFIABLE", "DERIVE", "DECRYPT", "UNWRAP"]:
            require(attributes["CKA_" + attribute] is False, "Unexpected token capability enabled")
        require(attributes["CKA_KEY_TYPE"] == 3, "Token key is not EC")
        require(tested["privateKeyCountBeforeAndAfter"] == [1, 1] and tested["attributesUnchanged"] is True,
                "Token object inventory or protection attributes changed")
        attempts = tested["attempts"]
        require(len(attempts) == len(EXPECTED_RETURNS) and
                {item["operation"]: item["returnCode"] for item in attempts} == EXPECTED_RETURNS,
                "Export probe did not reach the expected protection rejection")
        require(tested["signatureVerified"] is True and len(bytes.fromhex(tested["signatureHex"])) == 96,
                "Token signing check failed")
        require({"CKM_ECDSA", "CKM_AES_CBC"}.issubset(tested["mechanisms"]), "Tested token mechanisms absent")
        boundary = command("observe", ["docker", "inspect", gateway, backend])
        containers = json.loads(boundary["stdout"])
        client = one(containers, lambda value: value["Name"] == "/" + gateway, "Missing gateway container")
        server = one(containers, lambda value: value["Name"] == "/" + backend, "Missing backend container")
        require(client["State"]["Running"] and server["State"]["Running"], "Token container is not running")
        require(not client["HostConfig"]["Privileged"] and not server["HostConfig"]["Privileged"],
                "Unexpected privileged token container")
        require(client["HostConfig"]["PidMode"] != "host" and server["HostConfig"]["PidMode"] != "host",
                "Unexpected host process namespace")
        require(server["HostConfig"]["NetworkMode"] == "none", "Token backend network boundary differs")
        storage = one(server["Mounts"], lambda value: value["Destination"] == "/token", "Missing backend token storage")
        socket = one(server["Mounts"], lambda value: value["Destination"] == "/run/p11", "Missing backend token socket")
        client_socket = one(client["Mounts"], lambda value: value["Destination"] == "/run/p11", "Missing gateway token socket")
        require(socket["Source"] == client_socket["Source"] and not client_socket["RW"], "Token socket mount differs")
        forbidden = [Path(storage["Source"]), Path("/var/run/docker.sock"), Path("/run/docker.sock")]
        require(all(not any(Path(mount["Source"]) == item or Path(mount["Source"]) in item.parents or
                            item in Path(mount["Source"]).parents
                            for item in forbidden) for mount in client["Mounts"]), "Gateway can access protected host storage")
        require(all(mount["Destination"] != "/token" for mount in client["Mounts"]), "Gateway has token storage mounted")
        absent = command("observe", ["docker", "exec", gateway, "ls", "/token/objects"], successful=False)
        require(absent["returncode"] != 0 and "No such file" in absent["stderr"], "Backend files visible at gateway")
        private = command("observe", ["docker", "exec", gateway, "find", "/etc/swanctl/private", "-type", "f"])
        require(not private["stdout"].strip(), "Gateway contains private PEM files")
        sas = command("observe", ["docker", "exec", gateway, "swanctl", "--list-sas"])
        require("ESTABLISHED, IKEv2" in sas["stdout"] and "INSTALLED, TUNNEL" in sas["stdout"] and
                gateway + ".lab" in sas["stdout"], "Token gateway authentication/tunnel missing")
        peer = "12" if suffix == "A" else "11"
        local = "11" if suffix == "A" else "12"
        ping = command("observe", ["docker", "exec", gateway, "ping", "-n", "-I", "192.0.2." + local,
                                     "-c", "3", "-W", "1", "192.0.2." + peer])
        require("3 packets transmitted, 3 received" in ping["stdout"], "Token VPN traffic probe failed")
        results.append({"device": gateway, "backend": backend, "generation": generated, "exercise": tested,
                        "gatewayContainer": client, "backendContainer": server,
                        "securityAssociations": sas["stdout"], "protectedTraffic": ping["stdout"],
                        "observations": ["bootstrap:" + generation["id"], "observe:" + exercise["id"],
                                         "observe:" + boundary["id"], "observe:" + sas["id"], "observe:" + ping["id"]]})
    require(results[0]["exercise"]["publicSPKISha256"] != results[1]["exercise"]["publicSPKISha256"],
            "Token gateways share a signing key")
    report = {"devices": [{"id": row["device"], "backend": row["backend"]} for row in results],
              "token_keys": results, "observations": observations, "coverage": [{"scope": text} for text in context["scope"]],
              "context": context, "manifestSha256": manifest_hash, "scope": [SCOPE], "projectionVersion": "pkcs11-token-boundary-v1"}
    return {"runtime_backend": "native-Linux-PKCS11-RPC"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    row = one(report["observations"], lambda row: row["id"] == observation, "Unknown token observation")
    return row["record"]["stderr" if stderr else "stdout"]


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
