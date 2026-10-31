"""Import positive certificate, mutual-policy and ESP lifetime subclauses."""
import argparse
import json
from pathlib import Path
import re

from import_classical_ike import parse as classical
from import_ike_contexts import parse as contexts
from loaded_policy import parse_configuration
from validate_evidence import require


def lifetime_rows(text):
    starts = list(re.finditer(r"(?m)^src ([0-9.]+) dst ([0-9.]+)$", text))
    require(starts, "Empty ESP lifetime inventory")
    rows = []
    for index, start in enumerate(starts):
        block = text[start.start():starts[index+1].start() if index+1 < len(starts) else len(text)]
        spi = re.findall(r"proto esp spi 0x([0-9a-f]+)\(", block)
        hard = re.findall(r"expire add: soft \d+\(sec\), hard (\d+)\(sec\)", block)
        require(len(spi) == len(hard) == 1, "Missing or ambiguous ESP hard lifetime")
        seconds = int(hard[0])
        require(0 < seconds <= 28800, "ESP hard lifetime is disabled or exceeds eight hours")
        rows.append({"spi": int(spi[0], 16), "hard_seconds": seconds})
    require(len({r["spi"] for r in rows}) == len(rows), "Duplicate ESP lifetime identity")
    return rows


def parse(bundle, public):
    bundle = Path(bundle)
    algorithms = classical(bundle, public)
    sessions = contexts(bundle)
    snapshot = json.loads((bundle/"snapshot.json").read_text())
    tunnels = {t["device_id"]: t for t in snapshot["tunnels"]}
    devices = {d["id"]: d for d in snapshot["devices"]}
    records = {r["device"]: r for r in sessions["endpoints"]}
    policies = []
    certificates = []
    for name, key in algorithms["credential_keys"].items():
        record = records[name]
        peer = record["peer"]
        require(peer in algorithms["credential_keys"], "Peer credential missing")
        cfg = parse_configuration(tunnels[name]["loaded_public_configuration"])[record["connection"]]
        require(cfg["local"]["auth"] == cfg["remote"]["auth"] == "ecdsa-384-sha384",
                "Certificate authentication is not required")
        require(cfg["local"]["certs"] == "cert.pem" and cfg["remote"]["cacerts"] == "ca.pem",
                "Selected credential/anchor file differs")
        require(cfg["remote"]["id"] == algorithms["credential_keys"][peer]["local_id"],
                "Required peer identity differs from loaded peer credential")
        certificates.append({"device": name, "fingerprint": key["certificate_sha256"]})
        policies.append({"device": name, "peer": peer, "local_certificate": key["certificate_sha256"],
                         "required_peer_identity": cfg["remote"]["id"]})
    require(len({c["fingerprint"] for c in certificates}) == len(certificates),
            "Loaded certificate reused across devices")
    lifetimes = []
    for name, record in records.items():
        command = ["docker", "exec", devices[name]["namespace"], "ip", "-s", "xfrm", "state", "list", "nokeys"]
        selected = [o for o in snapshot["observations"] if o["device_id"] == name and o["command"] == command]
        require(len(selected) == 1, "Missing complete lifetime observation")
        observation = selected[0]
        require(observation["returncode"] == 0 and observation["parse_status"] == "parsed" and
                observation.get("error") is None, "Failed lifetime observation")
        raw = json.loads((bundle/observation["raw_path"]).read_text())
        rows = lifetime_rows(raw["stdout"])
        require({r["spi"] for r in rows} == {record["inbound_spi"], record["outbound_spi"]},
                "Lifetime inventory differs from installed reciprocal session")
        lifetimes.extend({"device": name, "observation": observation["id"], **row} for row in rows)
    return {"classical_binding": algorithms, "session_binding": sessions,
            "certificates": certificates, "policies": policies, "lifetimes": lifetimes,
            "scope": [
                "Eight shared Inner loaded endpoint certificates, ten gateway installed ESP lifetime inventories, and reciprocal established Inner IKE sessions.",
                "Certificate uniqueness uses actual DER digests under the recorded collision/unchanged-association contract. Complete CA chains, revocation/expiry checks and factory-certificate removal remain separate.",
                "The mutual-policy theorem interprets mandatory ECDSA certificate authentication through standard strongSwan/IKE verification-before-admission behavior. ESTABLISHED records provide actual nonempty session evidence; no synthetic verification log is asserted.",
                "Positive XFRM expire-add hard values are elapsed seconds. A zero use timer, disabled IKE rekey timer, reauthentication interval and IKE hard lifetime are not substituted for the ESP hard lifetime.",
                "Collector completeness and unchanged configuration/session interpretation across the stated observation interval remain explicit. Future reconfiguration is outside the selected claim."
            ]}


def generate(data):
    q = json.dumps
    certs = ", ".join("⟨"+q(c["device"])+", "+q(c["fingerprint"])+"⟩" for c in data["certificates"])
    policies = ", ".join("⟨"+", ".join(q(p[k]) for k in ["device","peer","local_certificate","required_peer_identity"])+", true⟩" for p in data["policies"])
    values = ", ".join(str(r["hard_seconds"]) for r in data["lifetimes"])
    return """import TDN.Targets.VPNObservedClauses

namespace TDN.Imported.FreshVPNObservedClauses
open Targets

def certificates : List LoadedDeviceCertificate := ["""+certs+"""]
def policies : List CertificateAuthenticationPolicy := ["""+policies+"""]
def espHardSeconds : List Nat := ["""+values+"""]

lemma fingerprints_unique : (certificates.map LoadedDeviceCertificate.fingerprint).Nodup := by decide
lemma peer_verification_required : ∀ policy ∈ policies, policy.requiresPeerCertificate = true := by decide
lemma esp_lifetimes_positive_and_bounded : ∀ seconds ∈ espHardSeconds, PositiveESPLifetime seconds := by
  unfold PositiveESPLifetime
  decide

theorem loaded_certificates_are_unique_per_device :
    ∀ a ∈ certificates, ∀ b ∈ certificates, a.device ≠ b.device → a.fingerprint ≠ b.fingerprint :=
  distinct_loaded_certificates_from_fingerprint_inventory certificates fingerprints_unique

theorem every_selected_active_esp_age_is_below_eight_hours
    (hard age : Nat) (member : hard ∈ espHardSeconds) (active : age < hard) : age < 28800 :=
  active_esp_age_below_required_maximum hard age (esp_lifetimes_positive_and_bounded hard member) active

theorem admitted_selected_peers_require_mutual_certificate_verification
    (left right : CertificateAuthenticationPolicy) (hl : left ∈ policies) (hr : right ∈ policies)
    (leftVerifiedRight rightVerifiedLeft : Bool)
    (leftAccepted : CertificatePeerAccepted left leftVerifiedRight)
    (rightAccepted : CertificatePeerAccepted right rightVerifiedLeft) :
    leftVerifiedRight = true ∧ rightVerifiedLeft = true :=
  mutual_certificate_admission_requires_both_verifications left right
    (peer_verification_required left hl) (peer_verification_required right hr)
    leftVerifiedRight rightVerifiedLeft leftAccepted rightAccepted

lemma nonempty_selected_certificates_and_lifetimes : certificates.length = 8 ∧ espHardSeconds.length = 20 := by decide

end TDN.Imported.FreshVPNObservedClauses
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--public", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.bundle, args.public)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2)+"\n")
    print(json.dumps({"certificates": len(data["certificates"]), "lifetimes": len(data["lifetimes"])}))


if __name__ == "__main__":
    main()
