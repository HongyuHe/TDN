"""Run existing TDN parsers and models on fresh public observations.

The driver accepts observations and ordinary deployment inventory. It never reads
the injection profiles, mutation journals, ground-truth probes, or agent findings.
"""

import argparse
import hashlib
import ipaddress
import itertools
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from common import BASE, ROOT, now, sha256, write_json

sys.path.insert(0, str(ROOT / "mcp"))
sys.path.insert(0, str(ROOT / "scripts/construction"))
from tdn_evidence.parsers.correspondence import parse_iptables_save
from tdn_evidence.parsers.packet_policy import parse_rule
from tdn_evidence.parsers.execution import policy_blocks, association_json
from tdn_evidence.projections import atom_json
from tdn_evidence.native_authentication_services import loaded_fields
from loaded_policy import parse_configuration, proposal_modes
from check_configuration_records import vpn_mode


def seconds(value):
    match = re.fullmatch(r"(\d+)([smhd]?)", value)
    if not match:
        raise ValueError("Unrecognized lifetime")
    return int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]


def observed(device, kind):
    row = device["observations"][kind]
    if row["returncode"]:
        raise ValueError("Failed observation: " + kind)
    return row["stdout"]


def packet(source, destination, protocol, ingress, egress, sport, dport):
    return {"source": source, "destination": destination, "protocol": protocol,
            "ingress": ingress, "egress": egress, "sourcePort": sport,
            "destinationPort": dport, "ipv4HeaderWords": 5,
            "matchedInboundPolicyIds": [], "matchedOutboundPolicyIds": [],
            "connectionState": "NEW", "ipv6NextHeader": 0, "icmpType": 0,
            "icmpCode": 0, "hopLimit": 64, "etherType": None,
            "payloadBytes": None, "connectionId": None, "networkBytes": 44,
            "ipv4FragmentOffset": 0}


def route_output(routes, destination):
    matches = []
    for row in routes:
        if row.get("table", "main") != "main" or row.get("type", "unicast") != "unicast":
            continue
        prefix = ipaddress.ip_network(row.get("dst", "default").replace("default", "0.0.0.0/0"))
        if ipaddress.ip_address(destination) in prefix and "dev" in row:
            matches.append((-prefix.prefixlen, row.get("metric", 0), row["dev"]))
    return min(matches)[2] if matches else None


def seeds(rule, chain, record, routes):
    fields = {a["kind"]: a for a in rule["atoms"]}
    if rule["verdict"] != "allow" or any(k in fields for k in ["inboundPolicy", "outboundPolicy"]):
        return []
    if "connectionStates" in fields and "NEW" not in fields["connectionStates"]["values"]:
        return []
    addresses = [int(ipaddress.ip_interface(i["address"]).ip)
                 for i in record["interfaces"] if i.get("address") and ":" not in i["address"]]
    if not addresses:
        return []

    def values(name, fallback):
        field = fields.get(name)
        if field is None:
            return fallback
        if "values" in field:
            return field["values"]
        if "value" in field:
            return [field["value"]]
        low, high = field["low"], field["high"]
        return sorted({low, min(low + 1, high), high})

    interfaces = [i["name"] for i in record["interfaces"]]
    sources = values("sourceRange", addresses)
    destinations = values("destinationRange", addresses)
    incoming = values("ingress", interfaces)
    outgoing = values("egress", [""] if chain == "INPUT" else interfaces)
    protocols = values("protocol", ["tcp", "udp", "gre", "icmp"])
    source_ports = values("sourcePorts", [32000])
    destination_ports = values("destinationPorts", [1, 500, 4500, 65535])
    result = []
    for src, dst, ingress, egress, proto, sp, dp in itertools.product(
            sources, destinations, incoming, outgoing, protocols, source_ports, destination_ports):
        if ingress == "lo" or (chain == "INPUT" and egress):
            continue
        if chain == "FORWARD" and route_output(routes, dst) != egress:
            continue
        result.append(packet(src, dst, proto, ingress, egress, sp, dp))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("--capture", default="final")
    args = parser.parse_args()
    started = time.monotonic()
    run = BASE / "runs" / args.run_id
    output = run / ("tdn-" + args.capture)
    output.mkdir(exist_ok=False)
    networks = json.loads((run / "deployments.json").read_text())
    findings, diagnostics, samples, certificates, inputs, coverage = [], [], [], [], [], []

    def finding(network, device, requirement, title, evidence, method, code):
        findings.append({"network": network, "devices": [device], "requirement_ids": [requirement],
                         "title": title, "evidence": evidence, "method": method, "code": code})

    for network in networks:
        net = network["id"]
        path = run / "raw" / args.capture / (net + ".json")
        inputs.append({"path": str(path.relative_to(ROOT)), "sha256": sha256(path.read_bytes())})
        capture = json.loads(path.read_text())
        inventory = {d["id"]: d for d in network["spec"]["devices"]}
        for device in capture["devices"]:
            name = device["id"]
            record = inventory[name]
            role = record["role"]
            if role not in {"inner", "outer", "firewall", "gray-firewall"}:
                continue
            if role in {"inner", "outer"}:
                try:
                    runtime = observed(device, "ipsec_connections")
                    remote = loaded_fields(runtime, "remote-1")
                    if remote["class"] != "public key":
                        finding(net, name, "MSC-VG-6", "Loaded peer policy uses non-certificate authentication",
                                remote, "existing_configuration_audit", "scripts/construction/check_configuration_records.py:152")
                    version = re.search(r"\bversion=IKEv(\d+)\b", runtime)
                    if version and int(version[1]) != 2:
                        finding(net, name, "MSC-VG-9", "Loaded connection permits IKEv1",
                                version.group(), "existing_configuration_audit", "scripts/construction/check_configuration_records.py:26")
                    text = observed(device, "ipsec_config")
                    try:
                        config = parse_configuration(text)
                        for connection_name, conn in config.items():
                            if seconds(conn["reauth_time"]) > 86400:
                                finding(net, name, "MSC-VG-13", "Configured reauthentication interval exceeds 24 hours",
                                        {"connection": connection_name, "reauth_time": conn["reauth_time"]},
                                        "formalized_configuration_clause", "TDN/Requirements/CsfcRoleObligationRecords.lean:484")
                            for child_name, child in conn["children"].items():
                                if seconds(child["life_time"]) > 28800:
                                    finding(net, name, "MSC-VG-14", "Configured ESP hard lifetime exceeds eight hours",
                                            {"child": child_name, "life_time": child["life_time"]},
                                            "formalized_configuration_clause", "TDN/Requirements/CsfcRoleObligationRecords.lean:484")
                                if child["mode"] != "tunnel" and "mode=" + child["mode"].upper() in runtime:
                                    requirement = "MSC-IR-1" if role == "inner" else "MSC-OR-1"
                                    finding(net, name, requirement, "Loaded ESP child uses transport mode",
                                            {"child": child_name, "mode": child["mode"]},
                                            "formalized_configuration_clause", "TDN/Requirements/EncryptionComponentNoBypassSpec.lean:59")
                    except (ValueError, KeyError) as error:
                        diagnostics.append({"network": net, "device": name, "scope": "public IPsec configuration", "error": str(error)})
                    cert = observed(device, "certificate")
                    fp = re.search(r"(?im)^sha256 Fingerprint=(.+)$", cert)
                    if fp:
                        certificates.append({"network": net, "device": name, "fingerprint": fp[1]})
                except (ValueError, KeyError) as error:
                    diagnostics.append({"network": net, "device": name, "scope": "authentication", "error": str(error)})
            try:
                raw = observed(device, "firewall4")
                text = re.sub(r"(?m)^\[\d+:\d+\] ", "", raw)
                chains = parse_iptables_save(text)
                routes = json.loads(observed(device, "routes4"))
                policies = policy_blocks(observed(device, "policies"), 1 if role == "inner" else 2)
                out_policies = [association_json(row) for row in policies["out"]]
            except (ValueError, KeyError) as error:
                diagnostics.append({"network": net, "device": name, "scope": "packet prerequisites", "error": str(error)})
                continue
            for chain_name in ["INPUT", "FORWARD"]:
                chain = chains[chain_name]
                try:
                    rules = [parse_rule({"matches": {"iptables_tokens": r["tokens"]},
                                        "action": r["action"], "ordinal": i, "raw_text": r["raw"]})
                             for i, r in enumerate(chain["rules"])]
                    lean_rules = [{"atoms": [atom_json(a) for a in r["atoms"]], "verdict": r["verdict"]} for r in rules]
                    fallback = {"drop": "deny", "accept": "allow"}[chain["policy"]]
                except (ValueError, KeyError) as error:
                    diagnostics.append({"network": net, "device": name, "scope": chain_name, "error": str(error)})
                    continue
                generated = {json.dumps(p, sort_keys=True): p for r in rules for p in seeds(r, chain_name, record, routes)}
                coverage.append({"network": net, "device": name, "chain": chain_name,
                                 "rules": len(rules), "candidates": len(generated), "complete_rule_parse": True})
                zones = {i["name"]: i.get("zone") for i in record["interfaces"]}
                for p in generated.values():
                    tests = []
                    if role in {"inner", "outer"}:
                        tests.append(("MSC-PF-11", "ipv4_protocol", "", ""))
                    if role == "outer" and zones.get(p["ingress"]) == "black":
                        tests.append(("MSC-PF-9", "external_multicast", "", ""))
                    if chain_name == "FORWARD" and role in {"inner", "outer"}:
                        inside_zone, outside_zone = ("red", "gray") if role == "inner" else ("gray", "black")
                        a, b = zones.get(p["ingress"]), zones.get(p["egress"])
                        if {a, b} == {inside_zone, outside_zone} and p["protocol"] in {"tcp", "udp"} and p["destinationPort"] not in {500, 4500}:
                            outbound = a == inside_zone
                            req = ("MSC-IR-3" if outbound else "MSC-IR-5") if role == "inner" else ("MSC-OR-2" if outbound else "MSC-OR-5")
                            tests.append((req, "unprotected_forward", p["ingress"] if outbound else p["egress"], p["egress"] if outbound else p["ingress"]))
                    for req, kind, inside, outside in tests:
                        samples.append({"id": f"sample-{len(samples):06}", "network": net, "device": name,
                                        "chain": chain_name, "requirement": req, "kind": kind, "rules": lean_rules,
                                        "fallback": fallback, "packet": p, "inside": inside, "outside": outside,
                                        "egressPolicies": out_policies})
        grouped = {}
        for c in certificates:
            if c["network"] == net:
                grouped.setdefault(c["fingerprint"], []).append(c["device"])
        for fp, devices in grouped.items():
            if len(devices) > 1:
                finding(net, devices[0], "MSC-VG-4", "Two VPN gateways hold the same certificate",
                        {"devices": devices, "fingerprint": fp}, "existing_configuration_audit",
                        "scripts/construction/check_configuration_records.py:157")
                findings[-1]["devices"] = devices

    write_json(output / "samples.json", samples)
    write_json(output / "parse-coverage.json", coverage)
    write_json(output / "diagnostics.json", diagnostics)
    check_start = time.monotonic()
    process = subprocess.run(["lake", "env", "lean", "--run", str(BASE / "PacketChecks.lean"), str(output / "samples.json")],
                             cwd=ROOT, capture_output=True, text=True)
    check_seconds = time.monotonic() - check_start
    (output / "lean-stdout.txt").write_text(process.stdout)
    (output / "lean-stderr.txt").write_text(process.stderr)
    if process.returncode:
        raise RuntimeError(process.stdout + process.stderr)
    checked = json.loads(process.stdout.strip().splitlines()[-1])
    write_json(output / "packet-results.json", checked)
    by_id = {s["id"]: s for s in samples}
    retained = {}
    for row in checked:
        if row["violation"]:
            sample = by_id[row["id"]]
            key = (row["network"], row["device"], row["requirement"])
            if key not in retained:
                retained[key] = sample
                finding(row["network"], row["device"], row["requirement"],
                        "An accepted packet contradicts the checked TDN policy condition", sample,
                        "lean_packet_counterexample", "TDN/Models/IpsecAndAclRuleModel.lean:192")
    write_json(output / "certificates.json", {"witnesses": list(retained.values())})
    write_json(BASE / ".runtime/tdn-certificates.json", {"witnesses": list(retained.values())})
    proof_start = time.monotonic()
    proof = subprocess.run(["lake", "env", "lean", str(BASE / "CertificateChecks.lean")], cwd=ROOT, capture_output=True, text=True)
    (output / "certificate-typecheck.txt").write_text(proof.stdout + proof.stderr)
    if proof.returncode:
        raise RuntimeError(proof.stdout + proof.stderr)
    write_json(output / "results.json", {"ended_at": now(), "findings": findings, "inputs": inputs,
        "samples": len(samples), "certificate_count": len(retained), "diagnostic_count": len(diagnostics),
        "runtime_seconds": time.monotonic() - started, "lean_execution_seconds": check_seconds,
        "certificate_typecheck_seconds": time.monotonic() - proof_start,
        "scope": "Existing TDN parser/model functions with a new observation adapter and finite candidate generator; no mutation labels are inputs",
        "excluded": ["A parse failure or failed sufficient premise is not a detected violation",
                     "Configuration clause checks do not establish lifetime enforcement over time",
                     "The packet search is finite and incomplete; no complete-network pass is inferred"]})
    print(json.dumps({"output": str(output), "findings": len(findings), "samples": len(samples),
                      "certificates": len(retained), "diagnostics": len(diagnostics)}))


if __name__ == "__main__":
    main()
