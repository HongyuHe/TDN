"""Import full-level Gray address ownership and complete Outer IPv4 forwarding rules."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
from import_snapshot import parse_rule, lean_atom, lean_list, quoted
from import_trust_partition import lean_level, require
from validate_evidence import validate_bundle
from raw_correspondence import check_filter_correspondence, check_inner_tunnel_address_bindings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    parser.add_argument("--declaration", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    bundle = Path(args.snapshot)
    validation = validate_bundle(bundle)
    snapshot = json.loads((bundle / "snapshot.json").read_text())
    raw_filters = check_filter_correspondence(bundle, snapshot)
    raw_tunnels = check_inner_tunnel_address_bindings(bundle, snapshot)
    manifest = json.loads((bundle / "manifest.json").read_text())
    declarations = json.loads(Path(args.declaration).read_text())
    declaration = next(c for c in declarations["configurations"] if c["configuration_id"] == manifest["configuration_id"])
    levels = {c["id"]: c for c in declaration["security_levels"]}
    declared_level = {device: network["security_level_id"] for network in declaration["red_networks"] for device in network["inner_device_ids"]}
    devices = {d["id"]: d for d in snapshot["devices"]}
    expected_inner = {d for r in declaration["red_networks"] for d in r["inner_device_ids"]}
    observed_inner = {d["id"] for d in snapshot["devices"] if d["role"] == "inner"}
    require(expected_inner == observed_inner, "Incomplete Inner inventory")
    assignments = {}
    pairs = []
    for tunnel in snapshot["tunnels"]:
        if tunnel["layer"] != "inner":
            continue
        device = devices[tunnel["device_id"]]
        peer = devices[tunnel["peer_device_id"]]
        require(device["security_level_id"] == declared_level[device["id"]], "Inner level differs from declared Red attachment")
        require(peer["security_level_id"] == declared_level[peer["id"]], "Peer level differs from declared Red attachment")
        require(device["security_level_id"] == peer["security_level_id"], "Cross-level configured Inner tunnel")
        level = lean_level(levels[device["security_level_id"]])
        source = int(ipaddress.IPv4Address(tunnel["endpoints"]["local"]))
        destination = int(ipaddress.IPv4Address(tunnel["endpoints"]["remote"]))
        for address in [source, destination]:
            require(address not in assignments or assignments[address] == level, "Ambiguous Gray address level")
            assignments[address] = level
        pairs.append((source, destination, level))
    require({t["device_id"] for t in snapshot["tunnels"] if t["layer"] == "inner"} == expected_inner, "Missing Inner tunnel")
    outer_devices = {d["id"] for d in snapshot["devices"] if d["role"] == "outer"}
    chains = [chain for chain in snapshot["filters"] if chain["device_id"] in outer_devices and chain["family"] == 4 and chain["chain"] == "FORWARD" and chain["table"] == "filter"]
    require({c["device_id"] for c in chains} == outer_devices and len(chains) == len(outer_devices), "Outer forwarding hook inventory mismatch")
    rendered = []
    for chain in chains:
        require(chain["policy"] == "drop", "Outer forwarding default must deny")
        rules = [parse_rule(rule) for rule in chain["ordered_rules"]]
        rendered.append(lean_list(["⟨" + lean_list([lean_atom(atom) for atom in rule["atoms"]]) + ", ." + rule["verdict"] + "⟩" for rule in rules]))
    lines = ["import TDN.Requirements.MscAddressingRequirements", "", "namespace TDN.Deployments." + args.namespace, "", "set_option maxRecDepth 100000", "set_option maxHeartbeats 0", "", "def ranges : List (Addressing.Range SecurityLevel) := " + lean_list(["⟨" + str(address) + ", " + str(address) + ", " + level + "⟩" for address, level in sorted(assignments.items())]), "", "def pairs : List Requirements.IntendedAddressPair := " + lean_list(["⟨" + str(a) + ", " + str(b) + ", " + level + "⟩" for a, b, level in sorted(set(pairs))]), "", "def policies : List (List PacketPolicy.Rule) := " + lean_list(rendered), "", "lemma ranges_valid : ∀ r ∈ ranges, r.low ≤ r.high := by unfold ranges; decide", "lemma ranges_separated : Addressing.Separated ranges := by unfold Addressing.Separated ranges; decide", "lemma peers_share_full_level : ∀ p ∈ pairs, Addressing.Owns ranges p.source p.level ∧ Addressing.Owns ranges p.destination p.level := by", "  simp [pairs, ranges, Addressing.Owns, Addressing.Contains]", "lemma rules_name_intended_peers : ∀ rs ∈ policies, ∀ r ∈ rs, r.verdict = .allow → Requirements.RuleNamesPair pairs r := by", "  unfold policies pairs", "  decide", "", "theorem snapshot_RG014_outer_forwarding : Requirements.msc_gray_addressing_for_level_filtering ranges pairs policies :=", "  Requirements.gray_addressing_of_separated_ranges_and_named_rules ranges pairs policies", "    ranges_valid ranges_separated peers_share_full_level rules_name_intended_peers", "", "end TDN.Deployments." + args.namespace, ""]
    Path(args.output).write_text("\n".join(lines))
    report = {"snapshot": args.snapshot, "manifest_sha256": hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest(), "validation": validation, "raw_filter_correspondence": raw_filters, "raw_tunnel_bindings": raw_tunnels, "inner_devices": len(expected_inner), "gray_addresses": len(assignments), "intended_directed_pairs": len(set(pairs)), "outer_forward_chains": [c["id"] for c in chains], "scope": "All captured Outer IPv4 FORWARD hooks, with exact expected Outer and Inner inventory. Source/Destination fields are current Gray-side inner tunnel headers, before Outer encryption or after Outer decryption.", "remaining_scope": ["INPUT/OUTPUT control and management exceptions are accounted separately in RG039", "Gray firewall bridge policy is accounted separately in RG040", "Successful compilation checks literal source/destination rules; actual packet execution/refinement remains RG007/008/029/030 work", "Complete raw observations and source-level scenario labels remain explicit trust assumptions"]}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ["inner_devices", "gray_addresses", "intended_directed_pairs"]}))


if __name__ == "__main__":
    main()
