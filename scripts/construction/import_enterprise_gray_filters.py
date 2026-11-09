"""Bind retained Enterprise Gray IPv4 filter chains to their raw device commands."""
import argparse
import hashlib
import json
from pathlib import Path

from import_provenance import verified_files
from raw_correspondence import parse_iptables_save
from validate_evidence import require, unique_records, utc


def parse(root):
    root = Path(root)
    manifest, files = verified_files(root)
    phases = ["before-management-layer-loss.json", "stable-after.json"]
    require({"commands.json", "evidence.json", "case.json", *phases} <= files,
            "Missing Enterprise Gray source files")
    evidence = json.loads((root / "evidence.json").read_text())
    case = json.loads((root / "case.json").read_text())
    require(manifest.get("error") is None and evidence.get("error") is None,
            "Enterprise Gray collection reports an error")
    require(manifest["configuration_id"] == evidence["configuration_id"] == "central-gray-management-v3",
            "Unexpected Enterprise Gray configuration")
    require(manifest["runtime_backend"] == evidence["runtime_backend"] == "supplemental-linux-netns-static-routes",
            "Runtime backend changed")
    require({"NET-004-C01", "NET-012-C01", "NET-027-C02"} <= set(case["source_case_ids"]),
            "Source example mapping changed")
    commands = unique_records(json.loads((root / "commands.json").read_text()), "command")
    devices = unique_records(evidence["devices"], "device")
    selected = {name for name, device in devices.items() if
                device["role"].endswith("Gray-Firewall-Encryption-Component")}
    require(selected == {"IA", "IB"}, "Gray firewall inventory changed")
    records = []
    for phase in phases:
        observations = json.loads((root / phase).read_text())
        require(set(observations) == set(devices), "DatapathStage device inventory incomplete")
        for device in sorted(selected):
            observed = observations[device]["filters4"]
            command = commands.get(observed["observation_id"])
            require(command is not None and command["device_id"] == device,
                    "Filter observation device mismatch")
            require(command["command"] == ["ip", "netns", "exec", devices[device]["namespace"], "iptables-save"],
                    "Filter command does not read the selected device")
            require(command["returncode"] == observed["returncode"] == 0 and
                    command["stdout"] == observed["value"] and not command["stderr"].strip(),
                    "Filter observation differs from successful raw output")
            require(utc(manifest["started_at"]) <= utc(command["started_at"]) <=
                    utc(command["ended_at"]) <= utc(manifest["ended_at"]), "Filter observation time mismatch")
            #* This selected capture has one filter table. Reject extra tables instead of ignoring them.
            text = observed["value"]
            require([line for line in text.splitlines() if line.startswith("*")] == ["*filter"] and
                    text.splitlines().count("COMMIT") == 1, "Unexpected filter table inventory")
            chains = parse_iptables_save(text)
            require(set(chains) == {"INPUT", "FORWARD", "OUTPUT"}, "Filter chain inventory changed")
            require(chains["INPUT"] == {"policy": "accept", "rules": []} and
                    chains["OUTPUT"] == {"policy": "accept", "rules": []},
                    "Selected local INPUT/OUTPUT policy changed")
            require(chains["FORWARD"]["policy"] == "drop" and len(chains["FORWARD"]["rules"]) == 2,
                    "Selected FORWARD inventory/default changed")
            rendered = []
            for rule, incoming, outgoing, direction in zip(chains["FORWARD"]["rules"],
                    ["red", "gray"], ["gray", "red"], ["out", "in"]):
                require(rule["action"] == "accept" and rule["tokens"] ==
                        ["-i", incoming, "-o", outgoing, "-m", "policy", "--dir", direction,
                         "--pol", "ipsec", "--reqid", "100"], "Unsupported selected FORWARD rule")
                #* These rules constrain IPsec policy identity without selecting tunnel mode.
                atom = "outboundPolicy" if direction == "out" else "inboundPolicy"
                rendered.append('⟨[.ingress "' + incoming + '", .egress "' + outgoing +
                                '", .' + atom + ' 100], .allow⟩')
            records.append({"device": device, "phase": phase, "observation_id": command["id"],
                            "namespace": devices[device]["namespace"], "forward_rules": rendered,
                            "input_default": "allow", "input_rules": [], "forward_default": "deny"})
    return {"manifest_sha256": hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest(),
            "configuration": evidence["configuration_id"], "runtime_backend": evidence["runtime_backend"],
            "records": records, "whole_annex_established": False,
            "scope": ["Four raw-bound IPv4 observations cover both Gray firewall/encryptors before and after the recorded management-layer-loss experiment.",
                      "The selected policy guards name direction and request ID100 without a mode constraint. The imported policy-identity atoms do not infer tunnel mode.",
                      "The modeled FORWARD chain defaults to denial and requires an explicitly matching allow rule. INPUT and OUTPUT are empty with acceptance defaults.",
                      "The saved local INPUT chain cannot establish the annex's all-traffic default-denial requirement. Earlier hooks, IPsec selectors, IPv6 processing and actual packet arrival require separate analysis; no live counterexample is claimed.",
                      "The FORWARD rules lack explicit source-range atoms. That absence fails the sufficient interface/range certificate, but does not alone prove real source filtering absent: IPsec selectors may impose additional restrictions.",
                      "Repair and new evidence remain pending. No remote experiment or deployment change was made for this assessment."]}


def generate(data):
    entries = ["[" + ", ".join(row["forward_rules"]) + "]" for row in data["records"]]
    return """import TDN.Requirements.SharedEnterpriseGraySpecFiltering

namespace TDN.Deployments.FreshEnterpriseGrayFilters
open TDN.PacketPolicy

def forwardChains : List (List Rule) := [""" + ",\n  ".join(entries) + """]
def inputChains : List (List Rule × TDN.Filter.Verdict) :=
  [([], .allow), ([], .allow), ([], .allow), ([], .allow)]

/-- The four saved FORWARD chains require a matching explicit allow rule.
The conclusion covers first-match filter evaluation, with its saved DROP default. -/
theorem selected_forwarding_requires_an_explicit_allow (rules : List Rule)
    (_member : rules ∈ forwardChains) (packet : Packet) (accepted : Accepts rules packet) :
    ∃ rule ∈ rules, rule.toFilter.accepts packet = true ∧ rule.verdict = .allow := by
  obtain ⟨rule, member, matched, allowed⟩ :=
    TDN.Filter.allowed_has_matching_allow (rules.map Rule.toFilter) packet accepted
  obtain ⟨original, present, rfl⟩ := List.mem_map.mp member
  exact ⟨original, present, matched, allowed⟩

lemma input_defaults_are_acceptance : ∀ chain ∈ inputChains,
    chain.1 = [] ∧ chain.2 = .allow := by decide

/-- The complete saved INPUT chains accept in this selected filter model.
The observation identifies missing local-chain enforcement without inventing a
live arrival trace or asserting that other kernel hooks permit the packet. -/
theorem captured_local_input_accepts_every_packet (chain : List Rule × TDN.Filter.Verdict)
    (member : chain ∈ inputChains) (packet : Packet) :
    TDN.Filter.evaluate (chain.1.map Rule.toFilter) chain.2 packet = .allow := by
  obtain ⟨empty, default⟩ := input_defaults_are_acceptance chain member
  simp [empty, default, TDN.Filter.evaluate]

end TDN.Deployments.FreshEnterpriseGrayFilters
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    parser.add_argument("--lean-output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.snapshot)
    Path(args.lean_output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"filter_observations": len(data["records"]), "whole_annex_established": False}))


if __name__ == "__main__":
    main()
