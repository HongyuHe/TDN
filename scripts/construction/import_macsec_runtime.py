"""Bind public EAP logs and Linux MACsec runtime observations to universal local proofs."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from import_snapshot import lean_list, quoted
from validate_evidence import require


from tdn_evidence.parsers.public_manifest import validate_files


def parse(path):
    digest = validate_files(path)
    evidence = json.loads((path / "evidence.json").read_text())
    require(evidence["error"] is None, "EAP experiment failure")
    commands = json.loads((path / "commands.json").read_text())
    indexed = {r["id"]: r for r in commands}
    require(len(indexed) == len(commands), "Duplicate command ID")
    phase = json.loads((path / "stable-after.json").read_text())
    peers = [d for d in evidence["devices"] if d["role"] == "MACsec-peer"]
    require({d["id"] for d in peers} == {"P0", "P1"}, "Unexpected EAP peer inventory")
    configs, observations = [], []
    for device in peers:
        name = device["id"]
        for kind, suffix in [("interfaces", ["ip", "-j", "-d", "address"]),
                             ("macsec", ["ip", "-s", "macsec", "show"])]:
            value = phase[name][kind]
            raw = indexed[value["observation_id"]]
            require(raw["command"] == ["ip", "netns", "exec", device["namespace"]] + suffix and
                    raw["returncode"] == value["returncode"] == 0 and raw["stdout"] == value["value"],
                    "MACsec normalized observation differs from complete raw command")
            observations.append(raw["id"])
        interfaces = json.loads(phase[name]["interfaces"]["value"])
        macsec = [i for i in interfaces if i.get("linkinfo", {}).get("info_kind") == "macsec"]
        require(len(macsec) == 1, "MACsec interface coverage changed")
        interface = macsec[0]
        settings = interface["linkinfo"]["info_data"]
        require(settings["offload"] == "off", "Hardware offload needs a separate implementation contract")
        require(settings["cipher_suite"] == "GCM-AES-256" and settings["icv_len"] == 16,
                "Unexpected MACsec algorithm")
        logs = [r for r in commands if r["command"][0] == "cat" and
                r["command"][-1].endswith("/" + name + ".log")]
        require(len(logs) == 1 and logs[0]["returncode"] == 0, "Missing peer execution log")
        log = logs[0]["stdout"]
        require("CTRL-EVENT-EAP-SUCCESS" in log, "Missing successful EAP role execution")
        offsets = re.findall(r"create_transmit_sc -> (\S+) \(conf_offset=(\d+)\)", log)
        require(len(offsets) == 1, "Ambiguous transmit SC offset")
        sci = offsets[0][0].replace(":", "")
        require(sci == settings["sci"][:-4] + str(int(settings["sci"][-4:], 16)),
                "Logged transmit SCI differs from runtime interface")
        enabled = re.findall(r"macsec_drv_enable_controlled_port -> (TRUE|FALSE)", log)
        require(enabled, "No controlled port state")
        text = phase[name]["macsec"]["value"]
        summaries = re.findall(r"(?m)^\d+: " + re.escape(interface["ifname"]) + r": (.+)$", text)
        require(len(summaries) == 1, "Missing or ambiguous MACsec setting summary")
        tokens = summaries[0].split()
        require(len(tokens) % 2 == 0, "Malformed MACsec setting summary")
        summary = dict(zip(tokens[::2], tokens[1::2]))
        require(len(summary) * 2 == len(tokens) and set(summary) == {
            "protect", "validate", "sc", "sa", "encrypt", "send_sci", "end_station", "scb", "replay", "window"},
                "Unknown or duplicated MACsec summary field")
        for field, printed in [("protect", "protect"), ("encrypt", "encrypt"),
                               ("inc_sci", "send_sci"), ("es", "end_station"),
                               ("scb", "scb"), ("replay_protect", "replay")]:
            require(type(settings[field]) is bool and
                    summary[printed] == ("on" if settings[field] else "off"),
                    "MACsec JSON and text runtime settings differ")
        require(settings["validation"] in {"disabled", "check", "strict"} and
                summary["validate"] == settings["validation"] and
                type(settings["window"]) is int and 0 <= settings["window"] < 2 ** 32 and
                summary["window"] == str(settings["window"]),
                "MACsec receive validation/window observations differ")
        require(re.search(r"TXSC: " + settings["sci"] + r" on SA " + str(settings["encoding_sa"]), text),
                "Active runtime transmit SA differs")
        require("state on" in text and "OutPktsEncrypted" in text, "No installed encrypted transmit state")
        configs.append({"id": path.name + "/" + name, "controlledPortEnabled": enabled[-1] == "TRUE",
                        "protectFrames": settings["protect"], "encryptFrames": settings["encrypt"],
                        "confidentialityOffset": int(offsets[0][1]), "sa": settings["encoding_sa"],
                         "cipher": settings["cipher_suite"], "replay_window": settings["window"],
                        "receiveValidation": settings["validation"],
                        "replayProtection": settings["replay_protect"]})
        observations.append(logs[0]["id"])
    tls_logs = [r for r in commands if r["command"][0] == "cat" and
                r["command"][-1].endswith(".log") and "EVIDENCE effective TLS" in r["stdout"]]
    require(len(tls_logs) == 2, "Need both peer and authentication-server negotiated TLS logs")
    for row in tls_logs:
        suites = re.findall(r"EVIDENCE effective TLS version=(\S+) cipher=(\S+) group=(\S+)", row["stdout"])
        require(suites and set(suites) == {("TLSv1.3", "TLS_AES_256_GCM_SHA384", "MLKEM1024")},
                "Unexpected or mixed negotiated TLS suite")
        observations.append(row["id"])
    certificate_records = []
    for cert in ["as.pem", "peer.pem"]:
        rows = [r for r in commands if r["command"][:2] == ["openssl", "x509"] and
                any(value.endswith("/" + cert) for value in r["command"]) and r["command"][-2:] == ["-noout", "-text"]]
        require(len(rows) == 1 and rows[0]["returncode"] == 0, "Missing certificate algorithm observation")
        require("Public Key Algorithm: ML-DSA-87" in rows[0]["stdout"] and
                set(re.findall(r"Signature Algorithm: (\S+)", rows[0]["stdout"])) == {"ML-DSA-87"},
                "Certificate signature/key differs from objective suite")
        certificate_records.append(rows[0]["id"])
    observations += certificate_records
    return {"path": str(path), "manifest_sha256": digest, "ports": configs,
            "observations": observations, "negotiated_suite": [256, True, "mldsa87", "mlkem1024", "sha384"]}


def generate(cases, namespace="SnapshotMacsecRuntimeObservations"):
    ports = [p for case in cases for p in case["ports"]]
    values = [quoted(p["id"]) + ", { controlledPortEnabled := " + str(p["controlledPortEnabled"]).lower() +
              ", protectFrames := " + str(p["protectFrames"]).lower() + ", encryptFrames := " +
              str(p["encryptFrames"]).lower() + ", confidentialityOffset := " + str(p["confidentialityOffset"]) + " }"
              for p in ports]
    active = lean_list(["(" + quoted(p["id"]) + ", " + str(p["sa"]) + ")" for p in ports])
    source = """import TDN.Requirements.Cryptography
import TDN.Models.MacsecPortProtection

namespace TDN.Deployments.SnapshotMacsecRuntimeObservations
open LinkProtection

def ifaces : List (String × Config) := """ + lean_list(["(" + v + ")" for v in values]) + """
def installedAssociations : List (String × Nat) := """ + active + """
lemma installed_association_coverage : ∀ iface ∈ ifaces,
    ∃ binding ∈ installedAssociations, binding.1 = iface.1 := by
  unfold ifaces installedAssociations
  decide

lemma local_settings : ∀ iface ∈ ifaces, iface.2.protectFrames = true ∧
    iface.2.encryptFrames = true ∧ iface.2.confidentialityOffset = 0 := by
  unfold ifaces
  decide

theorem every_runtime_data_emission_is_encrypted (iface : String × Config)
    (member : iface ∈ ifaces) (association : Option Nat) (body : Nat) (wire : WireFrame Nat)
    (emitted : transmit iface.2 association body = some wire) : FullyEncrypted wire := by
  obtain ⟨protect, encrypt, zero⟩ := local_settings iface member
  exact every_emitted_frame_is_encrypted iface.2 protect encrypt zero association body wire emitted

theorem every_runtime_data_iface_blocks_absent_sa (iface : String × Config)
    (member : iface ∈ ifaces) (body : Nat) : transmit iface.2 none body = none :=
  absent_sa_blocks_data iface.2 (local_settings iface member).1 body

lemma runtime_ifaces_enabled : ∀ iface ∈ ifaces, iface.2.controlledPortEnabled = true := by
  unfold ifaces
  decide

theorem runtime_ifaces_permit_encrypted_emission (iface : String × Config)
    (member : iface ∈ ifaces) (association body : Nat) :
    transmit iface.2 (some association) body =
      some (.encrypted association iface.2.confidentialityOffset body) :=
  enabled_sa_emits_encryption iface.2 (runtime_ifaces_enabled iface member)
    (local_settings iface member).1 (local_settings iface member).2.1 association body

theorem observed_sa_allows_data (iface : String × Config) (member : iface ∈ ifaces) (body : Nat) :
    ∃ binding ∈ installedAssociations, binding.1 = iface.1 ∧
      transmit iface.2 (some binding.2) body =
        some (.encrypted binding.2 iface.2.confidentialityOffset body) := by
  obtain ⟨binding, installed, identity⟩ := installed_association_coverage iface member
  exact ⟨binding, installed, identity,
    runtime_ifaces_permit_encrypted_emission iface member binding.2 body⟩

def negotiatedSuite : Requirements.AlgorithmSuite := ⟨256, true, .mldsa87, .mlkem1024, .sha384⟩
lemma negotiated_suite_cnsa2 : Requirements.CNSA2 negotiatedSuite := by
  unfold Requirements.CNSA2 Requirements.ApprovedIntegrity negotiatedSuite
  decide

theorem observed_algorithms_satisfy_cnsa_choice :
    Requirements.msc_cnss_algorithm_policy [negotiatedSuite] := by
  intro suite member
  have same : suite = negotiatedSuite := by simpa using member
  subst suite
  exact Or.inr negotiated_suite_cnsa2

end TDN.Deployments.SnapshotMacsecRuntimeObservations
"""
    require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", namespace), "Invalid namespace")
    return source.replace("SnapshotMacsecRuntimeObservations", namespace)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundles", nargs="+")
    parser.add_argument("--namespace", default="SnapshotMacsecRuntimeObservations")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    cases = [parse(Path(path)) for path in args.bundles]
    Path(args.output).write_text(generate(cases, args.namespace))
    Path(args.report).write_text(json.dumps({"cases": cases, "scope": [
        "Universal local controlled-data-port emission and absent-SA properties under the Linux software MACsec/cryptographic implementation contract.",
        "The body in an encrypted constructor is semantic plaintext; confidentiality of ciphertext relies on the declared AES-GCM implementation assumption.",
        "Raw complete MACsec interfaces, settings, SCI, installed TXSA and peer logs are bound; data injected on a different unprotected physical interface is outside this local operation.",
        "Negotiated EAP TLS suite and certificate algorithms are observed; complete offered-suite policy, approved authorities/products, normative profile conformance and whole layered-network composition remain separate.",
        "Forward and reverse arrangements are distinct runtime cases and do not establish simultaneous dual-role use by one runtime instance."
    ]}, indent=2) + "\n")
    print(json.dumps({"cases": len(cases), "runtime_ports": sum(len(c["ports"]) for c in cases)}))


if __name__ == "__main__":
    main()
