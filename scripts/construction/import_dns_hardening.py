"""Bind exact IPv4 OUTPUT deny prefixes without abstracting their later policies."""
import argparse
import json
from pathlib import Path
import re
import shlex

from import_macsec_runtime import validate_files
from import_snapshot import quoted, parse_rule
from import_family_execution import render_rules
from validate_evidence import require


def parse_output_prefix(text, family):
    lines = [re.sub(r"^\[\d+:\d+\] ", "", line) for line in text.splitlines()]
    require(lines.count("*filter") == 1, "Missing or repeated filter table")
    start = lines.index("*filter")
    require("COMMIT" in lines[start:], "Incomplete filter table")
    table = lines[start + 1:lines.index("COMMIT", start)]
    output = [shlex.split(line) for line in table if line.startswith("-A OUTPUT ")]
    candidates = [i for i, tokens in enumerate(output) if tokens[:4] == ["-A", "OUTPUT", "-p", "tcp"]]
    require(candidates, "Missing DNS deny prefix")
    index = candidates[0]
    require(len(output[index:]) >= 2, "Missing DNS deny prefix")
    earlier = []
    for ordinal, tokens in enumerate(output[:index]):
        require("-j" in tokens, "Earlier OUTPUT rule has no action")
        jump = tokens.index("-j")
        require(jump == len(tokens) - 2, "Unsupported earlier action options")
        earlier.append(parse_rule({"matches": {"iptables_tokens": tokens[2:jump]},
                                  "action": tokens[-1].lower(), "ordinal": ordinal, "raw_text": " ".join(tokens)}))
    require(all({"kind": "connectionStates", "values": ["ESTABLISHED"]} in rule["atoms"] for rule in earlier),
            "Unsupported earlier prefix without established-only guard")
    protocols = []
    for tokens in output[index:index + 2]:
        require(len(tokens) == 12 and tokens[:3] == ["-A", "OUTPUT", "-p"],
                "Unexpected DNS prefix structure")
        protocol = tokens[3]
        reject_type = "icmp-port-unreachable" if family == 4 else "icmp6-port-unreachable"
        require(protocol in {"tcp", "udp"} and tokens == [
            "-A", "OUTPUT", "-p", protocol, "-m", protocol, "--dport", "53",
            "-j", "REJECT", "--reject-with", reject_type],
            "DNS rule has different guards, action or options")
        protocols.append(protocol)
    require(set(protocols) == {"tcp", "udp"}, "Incomplete transport coverage")
    return protocols, output, earlier


def parse(path):
    digest = validate_files(path)
    bundle = json.loads((path / "observations.json").read_text())
    require(bundle["error"] is None, "DNS collection failed")
    records = bundle["records"]
    require(len({r["id"] for r in records}) == len(records), "Duplicate observation ID")
    devices = sorted({r["command"][2] for r in records
                      if r["command"][:2] == ["docker", "exec"] and
                      r["command"][3:] == ["cat", "/etc/nsswitch.conf"]})
    require(set(devices) == {"ND_BLACK", "ND_G_A1", "ND_G_B1", "ND_O_A1", "ND_O_B1",
                             "ND_OF_A1", "ND_OF_B1"}, "Selected Linux device inventory differs")
    result = []
    for device in devices:
        for family, executable in [(4, "iptables-save"), (6, "ip6tables-save")]:
            matching = [r for r in records if r["command"] ==
                        ["docker", "exec", device, executable, "-c"]]
            require(matching, "Missing complete OUTPUT policy for address family")
            row = matching[-1]
            require(row["returncode"] == 0, "Failed policy readback")
            protocols, output, earlier = parse_output_prefix(row["stdout"], family)
            result.append({"device": device + "/IPv" + str(family), "family": family,
                           "observation_id": row["id"], "protocols": protocols,
                           "raw_output_rules": output, "earlier_rules": earlier,
                           "started_at": row["started_at"], "ended_at": row["ended_at"]})
    return {"bundle": str(path), "manifest_sha256": digest, "devices": result,
            "scope": "IPv4 and IPv6 NEW conventional DNS initiation, plus all conventional IPv6 DNS packets. Earlier established HTTPS reply rules are retained. Every later OUTPUT rule and fallback is universally quantified. PF state lookup, resolver/library behavior, complete service inventory and remote bootstrap remain separate."}


def generate(report):
    entries = []
    for row in report["devices"]:
        rules = ", ".join('{ atoms := [.protocol ' + quoted(protocol) +
                          ', .destinationPorts [53]], verdict := .deny }'
                          for protocol in row["protocols"])
        entries.append("{ name := " + quoted(row["device"]) + ", family := " + str(row["family"]) +
                       ", earlierRules := " + render_rules(row["earlier_rules"]) +
                       ", guards := [" + rules + "] }")
    return """import TDN.Requirements.Operations

namespace TDN.Deployments.FreshDNSHardening
open PacketPolicy

structure DNSDevice where
  name : String
  family : Nat
  earlierRules : List Rule
  guards : List Rule

def devices : List DNSDevice := [
  """ + ",\n  ".join(entries) + """]

lemma all_prefixes : ∀ device ∈ devices, device.guards =
    [{ atoms := [.protocol "tcp", .destinationPorts [53]], verdict := .deny },
     { atoms := [.protocol "udp", .destinationPorts [53]], verdict := .deny }] := by
  unfold devices
  decide

lemma earlier_state_guards : ∀ device ∈ devices, ∀ rule ∈ device.earlierRules,
    .connectionStates ["ESTABLISHED"] ∈ rule.atoms := by
  unfold devices
  decide

lemma ipv6_has_no_earlier_rules : ∀ device ∈ devices, device.family = 6 → device.earlierRules = [] := by
  unfold devices
  decide

lemma guarded_dns_is_denied (device : DNSDevice) (member : device ∈ devices)
    (suffix : List (Filter.Rule Packet)) (fallback : Filter.Verdict)
    (packet : Packet) (dns : Requirements.ConventionalDNS packet) :
    Filter.evaluate (device.guards.map Rule.toFilter ++ suffix) fallback packet = .deny := by
  apply Requirements.dns_egress_disabled_of_deny_prefix
  · rw [all_prefixes device member]
    simp
  · intro candidate request
    rw [all_prefixes device member]
    rcases request with ⟨iface, protocol | protocol⟩
    · refine ⟨{ atoms := [.protocol "tcp", .destinationPorts [53]], verdict := .deny }, by simp, ?_⟩
      simp [Rule.toFilter, MatchCondition.matchesPacket, iface, protocol]
    · refine ⟨{ atoms := [.protocol "udp", .destinationPorts [53]], verdict := .deny }, by simp, ?_⟩
      simp [Rule.toFilter, MatchCondition.matchesPacket, iface, protocol]
  · exact dns

theorem every_new_conventional_dns_request_is_denied (device : DNSDevice)
    (member : device ∈ devices) (suffix : List (Filter.Rule Packet))
    (fallback : Filter.Verdict) (packet : Packet) (dns : Requirements.ConventionalDNS packet)
    (newRequest : packet.connectionState = "NEW") :
    Filter.evaluate (device.earlierRules.map Rule.toFilter ++
      (device.guards.map Rule.toFilter ++ suffix)) fallback packet = .deny := by
  rw [Filter.evaluate_skips_nonmatching_prefix]
  · exact guarded_dns_is_denied device member suffix fallback packet dns
  · intro rule present
    obtain ⟨original, listed, rfl⟩ := List.mem_map.mp present
    cases equal : original.toFilter.accepts packet with
    | false => rfl
    | true =>
      have state := PacketPolicy.matching_atom equal (earlier_state_guards device member original listed)
      simp [MatchCondition.matchesPacket, newRequest] at state

theorem every_ipv6_conventional_dns_packet_is_denied (device : DNSDevice)
    (member : device ∈ devices) (ipv6 : device.family = 6)
    (suffix : List (Filter.Rule Packet)) (fallback : Filter.Verdict)
    (packet : Packet) (dns : Requirements.ConventionalDNS packet) :
    Filter.evaluate (device.earlierRules.map Rule.toFilter ++
      (device.guards.map Rule.toFilter ++ suffix)) fallback packet = .deny := by
  rw [ipv6_has_no_earlier_rules device member ipv6]
  exact guarded_dns_is_denied device member suffix fallback packet dns

end TDN.Deployments.FreshDNSHardening
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = parse(Path(args.bundle))
    Path(args.output).write_text(generate(report))
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"devices": len(report["devices"])}))


if __name__ == "__main__":
    main()
