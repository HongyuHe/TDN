"""Check complete Inner IKE offers against bound public endpoint certificates."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from import_authentication import certificate_parameters
from import_provenance import verified_files
from loaded_policy import loaded_policies, parse_configuration
from validate_evidence import require, safe_path, validate_bundle


def openssl(arguments, data=None):
    preferred = "/opt/homebrew/opt/openssl@3/bin/openssl"
    program = os.environ.get("TDN_OPENSSL") or (preferred if Path(preferred).is_file() else shutil.which("openssl"))
    require(program is not None, "OpenSSL is required to inspect public certificates")
    result = subprocess.run([program, *arguments], input=data, capture_output=True)
    require(result.returncode == 0, "Public certificate inspection failed")
    return result.stdout


def parse_offers(value):
    require(isinstance(value, str) and value.strip(), "IKE proposal list is empty")
    suites = []
    for proposal in value.split(","):
        ciphers, hashes, exchanges = [], [], []
        for token in proposal.strip().split("-"):
            if token == "aes256gcm16":
                ciphers.append(token)
            elif token in {"prfsha384", "prfsha512"}:
                hashes.append(token.removeprefix("prf"))
            elif token in {"ecp384", "modp3072", "modp4096"}:
                exchanges.append({"ecp384": "ecdhP384", "modp3072": "dh3072", "modp4096": "dh4096"}[token])
            else:
                raise ValueError("Unsupported or unapproved selected IKE token: " + token)
        require(ciphers and hashes and exchanges, "Incomplete IKE offer")
        require(len(ciphers) == len(set(ciphers)) and len(hashes) == len(set(hashes)) and
                len(exchanges) == len(set(exchanges)), "Duplicate IKE offer token")
        #* Algorithms of each transform type are alternatives; check every combination.
        suites.extend({"aesBits": 256, "gcm": True, "signature": "ecdsaP384sha384",
                       "establishment": exchange, "integrity": integrity}
                      for _, integrity, exchange in itertools.product(ciphers, hashes, exchanges))
    return suites


def parse(bundle, public_bundle):
    bundle, public_bundle = Path(bundle), Path(public_bundle)
    validation = validate_bundle(bundle)
    snapshot = json.loads((bundle / "snapshot.json").read_text())
    manifest = json.loads((bundle / "manifest.json").read_text())
    _, loaded = loaded_policies(bundle, snapshot)
    public_manifest, public_files = verified_files(public_bundle)
    require("bindings.json" in public_files, "Missing public certificate bindings")
    public = json.loads((public_bundle / "bindings.json").read_text())
    require(public["schema_version"] == "csfc-public-auth-bindings/v1", "Unsupported public binding schema")
    devices = {device["id"]: device for device in snapshot["devices"]}
    expected = {name for name, device in devices.items() if device["role"] == "inner"}
    identities = [row for row in public["devices"] if row["configuration_id"] == manifest["configuration_id"]]
    require(expected and {row["device_id"] for row in identities} == expected and len(identities) == len(expected),
            "Complete Inner certificate inventory required")
    identities = {row["device_id"]: row for row in identities}
    tunnels = {row["device_id"]: row for row in snapshot["tunnels"]}
    credentials = {row["device_id"]: row for row in snapshot["credentials"]}
    observations = {row["id"]: row for row in snapshot["observations"]}
    keys = {}
    for device, identity in identities.items():
        require(identity["peer_device_id"] in expected, "Peer certificate binding is missing")
        certs = [cert for cert in identity["certificates"] if cert["source"] == "loaded-daemon-certificate" and
                 cert["certificate_sha256"] == identity["own_certificate_sha256"]]
        require(len(certs) == 1, "Own loaded certificate is ambiguous")
        certificate = certs[0]
        pem = safe_path(public_bundle, certificate["pem_path"])
        der = openssl(["x509", "-in", str(pem), "-outform", "DER"])
        require(hashlib.sha256(der).hexdigest() == certificate["certificate_sha256"], "Certificate DER digest differs")
        text = openssl(["x509", "-in", str(pem), "-noout", "-text", "-fingerprint", "-sha256"]).decode()
        #* OpenSSL versions differ in spaces around the subject CN equals sign.
        parameters = certificate_parameters(text.replace("Subject: CN=", "Subject: CN = "),
                                            identity["configured_local_id"])
        public_key = openssl(["x509", "-in", str(pem), "-pubkey", "-noout"])
        spki = openssl(["pkey", "-pubin", "-outform", "DER"], public_key)
        require(hashlib.sha256(spki).hexdigest() == certificate["public_key_spki_sha256"] == identity["own_public_key_spki_sha256"],
                "Public-key identity differs")
        prefix = ["docker", "exec", devices[device]["namespace"]]
        def raw(name, command):
            oid = identity["observations"][name]
            filename = "raw/" + oid + ".json"
            require(filename in public_files, "Unmanifested public observation")
            record = json.loads((public_bundle / filename).read_text())
            require(record["id"] == oid and record["returncode"] == 0 and record["command"] == prefix + command,
                    "Public observation command/device mismatch")
            return record["stdout"]
        config = tunnels[device]["loaded_public_configuration"]
        require(raw("loaded-public-configuration", ["cat", "/etc/swanctl/swanctl.conf"]) == config,
                "Certificate capture configuration differs from loaded snapshot")
        require(pem.read_text().strip() in raw("loaded-public-certificates", ["swanctl", "--list-certs", "--type", "x509", "--pem"]),
                "Own certificate absent from captured daemon certificates")
        credential = credentials[device]
        require(credential["status"] == "observed" and credential["authentication_kind"] == "certificate",
                "Snapshot credential is not observed certificate authentication")
        matching = []
        for oid in credential["observation_ids"]:
            observation = observations[oid]
            record = json.loads((bundle / observation["raw_path"]).read_text())
            if (observation["device_id"] == device and observation["returncode"] == 0 and
                    observation["command"] == prefix + ["swanctl", "--list-certs", "--utc"] and
                    record["stdout"] == credential["public_certificate_listing"]):
                matching.append(record["stdout"])
        require(len(matching) == 1, "Snapshot credential listing lacks a raw binding")
        blocks = re.split(r"(?=  subject:)", matching[0])
        own = [block for block in blocks if block.startswith('  subject:  "CN=' + identity["configured_local_id"] + '"\n')]
        require(len(own) == 1 and "pubkey:    ECDSA 384 bits, has private key" in own[0],
                "Snapshot own endpoint certificate is missing")
        ids = re.findall(r"(?m)^  keyid:\s+([0-9a-f:]+)$", own[0])
        require(ids == [":".join(hashlib.sha1(spki).hexdigest()[i:i+2] for i in range(0, 40, 2))],
                "Snapshot public-key identifier differs from retained certificate")
        keys[device] = {"certificate_sha256": certificate["certificate_sha256"], "parameters": parameters,
                        "local_id": identity["configured_local_id"], "remote_id": identity["configured_remote_id"]}
    offers = []
    for device in sorted(expected):
        identity = identities[device]
        for connection_name, config in parse_configuration(tunnels[device]["loaded_public_configuration"]).items():
            require(config["local"]["auth"] == config["remote"]["auth"] == "ecdsa-384-sha384",
                    "Explicit authentication algorithm constraint differs")
            require(config["local"]["id"] == keys[device]["local_id"] and
                    config["remote"]["id"] == keys[identity["peer_device_id"]]["local_id"] == keys[device]["remote_id"],
                    "Configured peer identity differs from measured certificate")
            offers.append({"device": device, "connection": connection_name, "suites": parse_offers(config["proposals"])})
    return {"configuration": manifest["configuration_id"], "snapshot_manifest_sha256": validation["source_manifest_sha256"],
            "public_manifest_sha256": hashlib.sha256((public_bundle / "manifest.json").read_bytes()).hexdigest(),
            "offers": offers, "credential_keys": keys, "complete_gateway_inventory": len(loaded),
            "checked_inner_inventory": len(expected), "whole_RG018_established": False, "whole_RG019_established": False,
            "scope": ["Complete loaded IKE offers for the selected Inner gateways, with both intended peer certificates bound to saved public keys and exact configured identities.",
                      "P-384 and certificate SHA384 parameters are read from public certificate bytes with OpenSSL. The snapshot's SHA1 public-key identifier is used only as a recorded identity binding, not as the required authentication hash.",
                      "The cross-capture identity binding assumes no SHA1 identifier collision or credential replacement and an unchanged association between the identifier, configured identity and loaded public key. Equal identifiers do not mathematically prove equal certificate bytes.",
                      "ECDSA-with-SHA384 is an explicit loaded authentication constraint. The proof concerns these captured fixed endpoint credentials and does not assert a general curve restriction for future alternative certificates.",
                      "Outer public certificate bindings, ESP algorithm duties, post-quantum objective exchange/profile duties and all other cryptographic purposes remain separate.",
                      "Negotiation must select from the complete recorded offer list. Correct strongSwan/OpenSSL behavior, collector truth and unchanged configuration during the modeled use remain assumptions. Matching observations at two times do not prove uninterrupted configuration stability."]}


def generate(data, namespace):
    entries = []
    for offer in data["offers"]:
        for suite in offer["suites"]:
            entries.append("⟨256, true, .ecdsaP384sha384, ." + suite["establishment"] + ", ." + suite["integrity"] + "⟩")
    return '''import TDN.Targets.ClassicalIKE

namespace TDN.Imported.''' + namespace + '''
open TDN.Targets

def offered : List AlgorithmSuite := [''' + ", ".join(entries) + ''']

lemma recorded_offer_inventory_nonempty : offered ≠ [] := by decide

theorem every_recorded_inner_ike_offer_uses_cnsa1 : ∀ suite ∈ offered, CNSA1 suite := by
  apply classical_ike_choices_from_local_checks
  · decide
  · decide
  · unfold offered ClassicalEstablishment; decide
  · unfold offered ApprovedIntegrity; decide

theorem every_selected_recorded_inner_ike_offer_uses_cnsa1
    (suite : AlgorithmSuite) (selected : suite ∈ offered) : CNSA1 suite :=
  negotiated_classical_ike_from_checked_offers offered every_recorded_inner_ike_offer_uses_cnsa1 suite selected

end TDN.Imported.''' + namespace + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    parser.add_argument("public_bindings")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--lean-output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.snapshot, args.public_bindings)
    Path(args.lean_output).write_text(generate(data, args.namespace))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"Inner_gateways": data["checked_inner_inventory"], "connections": len(data["offers"])}))


if __name__ == "__main__":
    main()
