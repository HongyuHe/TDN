"""Read retained signing observations without running any loader or executable."""
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from validate_evidence import require, safe_path, utc

COLLECTOR = "d5e92d4841cd3058f5fd805d32ae2a013cfc32eafcfd3d64e5a28abb1088c84e"
LOADER = "0221fd9da8fde9cffd9a6e700f52044bb8eb995934ad6dc12d01f9ea16a1cb7e"


def tlv(data, position, tag):
    require(position + 2 <= len(data) and data[position] == tag, "Unexpected public-key DER tag")
    position += 1
    length = data[position]
    position += 1
    if length >= 128:
        count = length & 127
        require(1 <= count <= 4 and position + count <= len(data), "Invalid DER length")
        require(data[position] != 0, "Nonminimal DER length")
        length = int.from_bytes(data[position:position + count], "big")
        require(length >= 128, "Nonminimal DER length")
        position += count
    require(position + length <= len(data), "Truncated public-key DER")
    return data[position:position + length], position + length


def public_key_bytes(pem):
    matched = re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?", pem)
    require(matched is not None, "Unsupported public-key PEM")
    der = base64.b64decode(b"".join(matched[1].splitlines()), validate=True)
    sequence, end = tlv(der, 0, 48)
    require(end == len(der), "Trailing public-key DER")
    algorithm, offset = tlv(sequence, 0, 48)
    oid, oid_end = tlv(algorithm, 0, 6)
    #* NIST CSOR assigns 2.16.840.1.101.3.4.3.19 to ML-DSA-87 with absent parameters.
    require(oid.hex() == "608648016503040313" and oid_end == len(algorithm),
            "Public key is not parameter-free ML-DSA-87")
    bits, end = tlv(sequence, offset, 3)
    require(end == len(sequence) and len(bits) > 1 and bits[0] == 0,
            "Malformed public-key bit string")
    return bits[1:]


def parse(root):
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text())
    files = {}
    for row in manifest["files"]:
        require(row["path"] not in files, "Duplicate signing artifact")
        data = safe_path(root, row["path"]).read_bytes()
        require(hashlib.sha256(data).hexdigest() == row["sha256"], "Signing artifact hash mismatch")
        files[row["path"]] = data
    require(set(files) == {"collector.source.py", "verified_loader.py", "publisher.pub",
                          "software-manifest.json", "software-manifest.sig", "observations.json"},
            "Signing artifact inventory changed")
    require(manifest["collector_sha256"] == COLLECTOR and
            hashlib.sha256(files["collector.source.py"]).hexdigest() == COLLECTOR and
            hashlib.sha256(files["verified_loader.py"]).hexdigest() == LOADER,
            "Unreviewed signing collector or loader source")
    public = public_key_bytes(files["publisher.pub"])
    software = json.loads(files["software-manifest.json"])
    require(software["schema"] == "signed-software-test/v1" and software["algorithm"] == "ML-DSA-87" and
            software["artifact"] == "twinet-linux" and type(software["bytes"]) is int and software["bytes"] > 0 and
            re.fullmatch(r"[0-9a-f]{64}", software["sha256"]), "Software manifest identity changed")
    observations = json.loads(files["observations.json"])
    require(observations.get("error") is None, "Signing collection reports an error")
    rows = observations["records"]
    require(len(rows) == 9, "Signing command inventory changed")
    times = [utc(row["at"]) for row in rows]
    require(times == sorted(times) and times[-1] <= utc(observations["at"]), "Signing command order changed")
    image = "twinet-msc:mldsa-construction-v2"
    require(rows[0]["command"] == ["docker", "image", "inspect", image, "--format", "{{.Id}}"] and
            rows[0]["returncode"] == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}\n", rows[0]["stdout"]),
            "Signing image identity absent")
    prefix = rows[1]["command"][:-3]
    require(len(prefix) == 12 and prefix[:6] == ["docker", "run", "--rm", "--network", "none", "-v"] and
            prefix[7] == prefix[9] == "-v" and prefix[11] == image, "Signing container command changed")
    private = prefix[6].removesuffix(":/private")
    base = str(PurePosixPath(private).parent.parent)
    require(prefix[6] == base + "/private/software-signing-v3:/private" and
            prefix[8] == base + "/exports/software-signing-v3:/public" and
            prefix[10] == base + "/scripts/twinet-linux:/payload/twinet-linux:ro",
            "Signing input mount binding changed")
    tails = [
        ["openssl", "version", "-a"],
        ["openssl", "genpkey", "-algorithm", "ML-DSA-87", "-out", "/private/publisher.key"],
        ["openssl", "pkey", "-in", "/private/publisher.key", "-pubout", "-out", "/public/publisher.pub"],
        ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", "/private/publisher.key", "-in", "/public/software-manifest.json", "-out", "/public/software-manifest.sig"]]
    for row, tail in zip(rows[1:5], tails):
        require(row["command"] == prefix + tail and row["returncode"] == 0,
                "Signing operation or key/manifest path changed")
    loader = ["python3", "/public/verified_loader.py"]
    changed_payload = list(prefix)
    changed_payload[10] = base + "/private/software-signing-v3/twinet-altered:/payload/twinet-linux:ro"
    changed_signature = prefix[:11] + ["-v", base + "/private/software-signing-v3/bad.sig:/public/software-manifest.sig:ro", image]
    expected = [(prefix + loader, 0, {"signature_verified": True, "payload_hash_verified": True, "executing_verified_fd": True}),
                (changed_payload + loader, 21, {"signature_verified": True, "payload_hash_verified": False, "executed": False}),
                (changed_signature + loader, 20, {"signature_verified": False, "executed": False})]
    for row, (command, code, result) in zip(rows[5:8], expected):
        require(row["command"] == command and row["returncode"] == code and not row["stderr"].strip(),
                "Recorded loader command/outcome changed")
        lines = row["stdout"].splitlines()
        require(lines and json.loads(lines[0]) == result, "Recorded loader output changed")
        require((code == 0 and "Usage:\n  twinet [command]" in row["stdout"]) or
                (code != 0 and len(lines) == 1), "Loader execution output differs")
    key_row = rows[8]
    require(key_row["command"] == prefix + ["openssl", "pkey", "-pubin", "-in", "/public/publisher.pub", "-text_pub", "-noout"] and
            key_row["returncode"] == 0 and key_row["stdout"].startswith("ML-DSA-87 Public-Key:\npub:\n"),
            "Observed public key type missing")
    key_text = key_row["stdout"].split("pub:\n", 1)[1]
    require(re.fullmatch(r"[0-9a-f:\s]+", key_text) is not None and
            bytes.fromhex(re.sub(r"[:\s]", "", key_text)) == public,
            "Observed public key bytes differ from saved key")
    return {"algorithm": "ML-DSA-87", "category": 5, "parameter": 87,
            "artifact": software["artifact"], "artifact_sha256": software["sha256"], "artifact_bytes": software["bytes"],
            "public_key_sha256": hashlib.sha256(files["publisher.pub"]).hexdigest(),
            "manifest_sha256": hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest(),
            "image": rows[0]["stdout"].strip(), "recorded_outcomes": ["executed", "hash_rejected", "signature_rejected"],
            "whole_RG073_established": False,
            "scope": ["The saved SPKI algorithm identifier and command-bound public-key dump agree on ML-DSA-87. CP Table2 supplies category5/parameter87.",
                      "The retained collector records one successful signed executable launch and two rejected controls. No loader or executable was rerun during import.",
                      "The importer checks retained source, command, key-identity and output bindings. It does not independently execute the ML-DSA verification algorithm on the retained signature.",
                      "The proof applies to the recorded executable algorithm choice. The artifact is a deployment utility, not a complete inventory of solution-device software or firmware.",
                      "The recorded manifest identifies payload bytes by hash and length; the executable itself is outside this bundle. Correct OpenSSL execution, trusted publisher-key provisioning, stable files, operating system and collector remain assumptions.",
                      "Same-file-descriptor execution does not establish that file contents cannot change concurrently. No claim about adversarial concurrent mutation, dependencies, firmware, boot verification or all loading paths is made."]}


def generate(data):
    return '''import TDN.Targets.SoftwareSignatures

namespace TDN.Imported.FreshSoftwareSignatures
open TDN.Targets

/-- The sole consumer is a laboratory deployment utility. It is not a replacement
for the complete CSfC solution-component inventory. -/
def recordedUses : List SoftwareSignatureUse :=
  [⟨"deployment-utility", "twinet-linux", .mldsa 5 87⟩]

lemma recorded_algorithm_is_approved : ∀ record ∈ recordedUses,
    ApprovedFirmwareSignature (fun _ => False) record.signature := by
  decide

theorem recorded_executable_has_table2_signature_choice :
    msc_software_firmware_signature_choice true ["deployment-utility"]
      (signaturesForComponent recordedUses) (fun _ => False) :=
  software_signature_choice_from_artifact_checks ["deployment-utility"] recordedUses
    (fun _ => False) (by decide) recorded_algorithm_is_approved

end TDN.Imported.FreshSoftwareSignatures
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    parser.add_argument("--lean-output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.snapshot)
    Path(args.lean_output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"algorithm": data["algorithm"], "whole_RG073_established": False}))


if __name__ == "__main__":
    main()
