"""Bind reviewed hostap derivation code, public vectors and final EAP runtime algorithms."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

from import_macsec_runtime import parse as parse_runtime, validate_files
from import_snapshot import lean_list, quoted
from validate_evidence import require

#* Pins identify the reviewed implementation contract, not a claim of verified C execution.
SOURCE_PINS = {
    "src/pae/ieee802_1x_key.c": "0d0c125a8b343e2aa404413706dea31df5a3a2ed8ce3db3e855865be7f6ab6d5",
    "src/crypto/crypto_openssl.c": "f30a502f853efa08e1da15bb9ca6c4456dc95f5d0de966db1e45a0acc5b16fb1",
    "src/pae/ieee802_1x_kay.c": "0ae4075f42ccf9b522dc73e2ee256552bdc0214780b3a730b7b18c28188dbbb5",
}
WRAPPERS = {
    "hostapd-2.12": ("src/ap/wpa_auth_kay.c", "39275037fb1e3b5bec3c2a970a4a62a215fb78272c2a7c07e9ed7b0ae26e2ebe",
                     "hostapd/hostapd", "23a5f3dfbaee5c2b4b54f16229d8274c3de7a760d30613a95db566a1acd78b1d"),
    "wpa_supplicant-2.12": ("wpa_supplicant/wpas_kay.c", "3d7d2d37a81a1d38007f193ee714f6e967487eda4f4fa2388fe79707e9486520",
                            "wpa_supplicant/wpa_supplicant", "aa5af96ee16645430271770a942ceefd2f86d62efbb25f2e76fe3595681d44a6"),
}
VECTOR_PIN = "0c74edde285fbfffdb83576982a42dab96879f6c21ab5285bbc810c4b90ad285"
LAUNCH_PIN = "ecf7a0a1a31640a20c2cf946c208560d27052ee3cc2e37794bc7b59080d03ea9"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(path):
    value = json.loads((path / "observations.json").read_text())
    require("error" in value and value["error"] is None, "collection has no explicit success")
    rows = value["records"]
    require(all(row["returncode"] == 0 for row in rows if "command" in row), "failed recorded command")
    return rows


def parse_vectors(path):
    digest = validate_files(path)
    require(sha(path / "vectors.json") == VECTOR_PIN, "published vector inventory changed")
    for relative, expected in {
        "build/vector-harness.c": "f3175f64e2690ff1edba76c10f75ba8962321ecd14729529973150d7b3f99284",
        "build/cmac-source-subset.c": "496ebf1af1969db2696995013c4e10fdb50b195bacbdbde358920d242fe18cbc",
    }.items():
        require(sha(path / relative) == expected, "reviewed vector harness/CMAC source changed")
    vectors = json.loads((path / "vectors.json").read_text())
    observed = records(path)
    probes = [row for row in observed if "probe" in row]
    require(len(probes) == len(vectors) == 12, "complete twelve-vector coverage required")
    require(len({row["probe"] for row in probes}) == 12, "duplicate vector observation")
    results = []
    for name, kind, key, context, size, expected in vectors:
        row = next((row for row in probes if row["probe"] == name), None)
        require(row is not None, "missing vector observation")
        require(row["command"][-5:] == ["./kdf-vectors", kind, key, context, str(size)],
                "vector command differs from published input")
        actual = row["stdout"].strip()
        require(re.fullmatch("[0-9a-f]+", actual) and len(actual) == size * 2,
                "invalid raw vector output")
        require(actual == row["observed_result"] == row["expected_result"] == expected,
                "raw vector output mismatch")
        results.append({"name": name, "kind": kind, "bytes": size,
                        "expected": expected, "observed": actual, "at": row["at"]})
    for relative, expected in SOURCE_PINS.items():
        if relative.endswith(("ieee802_1x_key.c", "crypto_openssl.c")):
            require(sha(path / ("runtime-" + Path(relative).name)) == expected,
                    "vector implementation differs from reviewed source")
    require(sha(path / "build/src/pae/ieee802_1x_key.c") == SOURCE_PINS["src/pae/ieee802_1x_key.c"],
            "compiled vector KDF source differs")
    return {"bundle": str(path), "manifest_sha256": digest, "results": results}


def parse_bindings(path, runtime):
    digest = validate_files(path)
    runtime_digest = validate_files(runtime)
    rows = records(path)
    metadata = json.loads((runtime / "observations.json").read_text())
    archive = runtime / "hostap-final-public-binaries.tar.gz"
    require(sha(archive) == metadata["archive_sha256"], "final binary archive differs")
    bindings = []
    with tarfile.open(archive, "r:gz") as tar:
        members = {member.name: member for member in tar.getmembers() if member.isfile()}
        for root, (wrapper, wrapper_pin, executable, binary_pin) in WRAPPERS.items():
            for relative, expected in {**SOURCE_PINS, wrapper: wrapper_pin}.items():
                local = root + "/" + relative
                matched = [row for row in rows if row.get("copied_public_source") == local]
                require(len(matched) == 1 and matched[0]["sha256"] == expected and sha(path / local) == expected,
                        "reviewed source binding changed")
            binary = "hostap-pq-delay-auth/" + root + "/" + executable
            selected = [row for row in metadata["selected_public_files"] if row["path"] == binary]
            require(len(selected) == 1 and selected[0]["sha256"] == binary_pin,
                    "final runtime binary metadata differs")
            matches = [member for name, member in members.items() if name.lstrip("./") == binary]
            require(len(matches) == 1, "final runtime binary archive coverage differs")
            content = tar.extractfile(matches[0]).read()
            require(hashlib.sha256(content).hexdigest() == binary_pin and len(content) == selected[0]["bytes"],
                    "final archived binary differs")
            commands = [row for row in rows if "command" in row and
                        any(argument.endswith("/" + root + "/" + executable + ":/runtime/program:ro")
                            for argument in row["command"])]
            require(len(commands) == 1 and commands[0]["stdout"].splitlines()[0] == binary_pin + "  /runtime/program"
                    and "OpenSSL 3.5.5" in commands[0]["stdout"], "runtime executable observation differs")
            bindings.append({"role": "authenticator" if root.startswith("hostapd") else "supplicant",
                             "source_root": root, "binary_path": binary, "binary_sha256": binary_pin,
                             "observed_at": commands[0]["at"], "cak_bytes": 32, "kek_bytes": 32,
                             "wrap_function": "aes_wrap", "ckn_bytes": 16,
                             "implementation_reading": "Both EAP wrappers request the first32 MSK bytes and CAK32; KAY sets KEK length to CAK length and passes that length to AES wrap."})
    return {"bundle": str(path), "manifest_sha256": digest,
            "runtime_bundle": str(runtime), "runtime_manifest_sha256": runtime_digest, "bindings": bindings}


def parse(cases, binding_path, runtime_path, vector_path):
    binding = parse_bindings(Path(binding_path), Path(runtime_path))
    vector = parse_vectors(Path(vector_path))
    runtime_cases = []
    for path in map(Path, cases):
        case = parse_runtime(path)
        require(sha(path / "collector.source.py") == LAUNCH_PIN, "reviewed runtime launch source differs")
        description = json.loads((path / "case.json").read_text())
        require(description["script_sha256"] == LAUNCH_PIN and
                {description["authenticator"], description["supplicant"]} == {"P0", "P1"},
                "runtime role/launch binding differs")
        case["roles"] = {description["authenticator"]: "authenticator", description["supplicant"]: "supplicant"}
        runtime_cases.append(case)
    require(runtime_cases, "empty MACsec runtime inventory")
    algorithms = []
    for case in runtime_cases:
        for port in case["ports"]:
            role = case["roles"][port["id"].rsplit("/", 1)[1]]
            source = next(row for row in binding["bindings"] if row["role"] == role)
            algorithms.append({"device": port["id"], "role": role,
                               "key_wrap_algorithm": "AES Key Wrap",
                               "key_wrap_bits": 8 * source["kek_bytes"],
                               "protection_algorithm": "AES GCM",
                               "protection_bits": int(port["cipher"].rsplit("-", 1)[1])})
    return {"cases": runtime_cases, "devices": algorithms,
            "source_bindings": binding, "finite_vectors": vector,
            "implementation_contract": [
                "Reviewed exact hostap EAP wrappers derive a32-byte CAK; shared KAY derives a CAK-sized KEK and calls AES wrap with that length. Standard AES/OpenSSL primitive semantics and correct compilation/execution are trusted.",
                "The retained collector launches the named binaries; later public source/binary collection binds their identities. The observation interval assumes those named build outputs were unchanged between execution and identity collection. There is no contemporaneous process-memory measurement.",
                "Every selected software MACsec data port has a raw-bound GCM-AES-256 interface. Hardware offload is excluded.",
                "The twelve public AnnexG vectors support only their finite inputs. Primary indexed IEEE excerpts have explicit incomplete-download provenance; full-standard conformance is not claimed.",
                "No source, binary or configuration pins represent secret values. The imported vector inputs are published public test data."
            ]}


def generate(data):
    entries = []
    for index, device in enumerate(data["devices"]):
        entries.append("⟨" + str(index) + ", " + quoted(device["key_wrap_algorithm"]) + ", " +
                       str(device["key_wrap_bits"]) + ", " + quoted(device["protection_algorithm"]) +
                       ", " + str(device["protection_bits"]) + "⟩")
    vectors = ["(" + quoted(row["name"]) + ", " + quoted(row["expected"]) + ", " +
               quoted(row["observed"]) + ")" for row in data["finite_vectors"]["results"]]
    return """import TDN.Targets.Protocol

namespace TDN.Imported.FinalMACsecAlgorithms

/-- Exact source/runtime bindings and their implementation contract are in the import report. -/
def devices : List Targets.MACsecAlgorithms := """ + lean_list(entries) + """
def publicVectorResults : List (String × String × String) := """ + lean_list(vectors) + """

lemma nonempty_devices : devices ≠ [] := by decide
lemma key_distribution_checks : ∀ device ∈ devices,
    device.keyWrapAlgorithm = "AES Key Wrap" ∧ device.keyWrapBits = 256 := by decide
lemma data_protection_checks : ∀ device ∈ devices,
    device.protectionAlgorithm = "AES GCM" ∧ device.protectionBits = 256 := by decide

theorem selected_runtime_algorithms :
    Targets.msc_macsec_encryption_and_key_wrap devices :=
  Targets.macsec_algorithms_from_local_checks devices key_distribution_checks data_protection_checks

/-- Finite public test outputs, with no universal KDF correctness claim. -/
theorem twelve_public_vectors_match : publicVectorResults.length = 12 ∧
    ∀ result ∈ publicVectorResults, result.2.1 = result.2.2 := by decide

end TDN.Imported.FinalMACsecAlgorithms
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", nargs="+")
    parser.add_argument("--bindings", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--vectors", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.cases, args.bindings, args.runtime, args.vectors)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"cases": len(data["cases"]), "vectors": len(data["finite_vectors"]["results"])}))


if __name__ == "__main__":
    main()
