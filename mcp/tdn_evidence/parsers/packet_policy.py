"""Interpret the supported ordered packet-filter subset as structured records."""
import ipaddress
from ..adapters import Unsupported
from .ipsec_framing import canonical_kind as canonical_ipsec_framing


def parse_rule(rule):
    matches = rule["matches"]
    if set(matches) != {"iptables_tokens"}:
        raise Unsupported("only literal iptables_tokens currently supported")
    tokens = matches["iptables_tokens"]
    atoms = []
    modules = []
    policy = {}
    icmp_protocols = []
    index = 0
    while index < len(tokens):
        key=tokens[index]
        if index+1 >= len(tokens):
            raise Unsupported("missing argument for " + key)
        value=tokens[index+1]
        index += 2
        if key in {"-s","-d"}:
            prefix=ipaddress.ip_network(value,strict=True)
            atoms.append({"kind":"sourceRange" if key=="-s" else "destinationRange","low":int(prefix.network_address),"high":int(prefix.broadcast_address),"family":prefix.version})
        elif key in {"-i","-o","-p"}:
            if key in {"-i","-o"} and "+" in value:
                raise Unsupported("interface wildcard")
            atoms.append({"kind":{"-i":"ingress","-o":"egress","-p":"protocol"}[key],"value":value})
        elif key == "-m":
            if value not in {"policy","multiport","u32","conntrack","tcp","udp","icmp","icmp6","hl","length","bpf"}:
                raise Unsupported("unknown module " + value)
            modules.append(value)
        elif key in {"--dir","--pol","--reqid","--mode"}:
            if key in policy:
                raise Unsupported("duplicate policy field")
            policy[key]=value
        elif key in {"--dports","--dport","--sports","--sport"}:
            values=value.split(",")
            if not all(v.isdigit() and 0 <= int(v) <= 65535 for v in values):
                raise Unsupported("unsupported port syntax")
            atoms.append({"kind":"sourcePorts" if key in {"--sport","--sports"} else "destinationPorts","values":[int(v) for v in values]})
        elif key in {"--icmp-type", "--icmpv6-type"}:
            fields = value.split("/")
            if len(fields) not in {1, 2} or not all(v.isdigit() and 0 <= int(v) <= 255 for v in fields):
                raise Unsupported("unsupported ICMP type/code syntax")
            icmp_protocols.append("icmp" if key == "--icmp-type" else "ipv6-icmp")
            atoms.append({"kind": "icmpType", "value": int(fields[0])})
            if len(fields) == 2:
                atoms.append({"kind": "icmpCode", "value": int(fields[1])})
        elif key == "--hl-eq":
            if not value.isdigit() or not 0 <= int(value) <= 255:
                raise Unsupported("unsupported hop-limit syntax")
            atoms.append({"kind": "hopLimit", "value": int(value)})
        elif key == "--bytecode":
            framing_kind = canonical_ipsec_framing(value)
            if framing_kind is None:
                raise Unsupported("unknown IPsec framing BPF program")
            atoms.append({"kind": framing_kind})
        elif key == "--length":
            endpoints = value.split(":")
            if len(endpoints) != 2 or not all(v.isdigit() for v in endpoints):
                raise Unsupported("unsupported packet length syntax")
            low, high = map(int, endpoints)
            if not 0 <= low <= high <= 65535:
                raise Unsupported("invalid packet length interval")
            atoms.append({"kind": "networkBytesRange", "low": low, "high": high})
        elif key == "--u32":
            if value != "0x0>>0x18&0xf=0x5":
                raise Unsupported("unsupported u32 expression")
            atoms.append({"kind":"ipv4HeaderWords","value":5})
        elif key == "--ctstate":
            states=value.split(",")
            if not set(states) <= {"NEW","ESTABLISHED","RELATED","INVALID","UNTRACKED"}:
                raise Unsupported("unknown connection state")
            atoms.append({"kind":"connectionStates","values":states})
        else:
            raise Unsupported("unsupported token " + key)
    for protocol in icmp_protocols:
        if {"kind": "protocol", "value": protocol} not in atoms:
            raise Unsupported("ICMP type flag lacks matching protocol")
    if any(atom["kind"] == "hopLimit" for atom in atoms) and "hl" not in modules:
        raise Unsupported("hop-limit flag lacks hl module")
    if any(atom["kind"] == "networkBytesRange" for atom in atoms) != ("length" in modules):
        raise Unsupported("packet length matcher and module disagree")
    if sum(atom["kind"] in ["ipsecUDPFraming", "ipsecUDPFramingWithOptions"] for atom in atoms) != modules.count("bpf"):
        raise Unsupported("BPF matcher and module disagree")
    if policy:
        if "policy" not in modules or set(policy)!={"--dir","--pol","--reqid","--mode"} or policy["--pol"]!="ipsec" or policy["--mode"]!="tunnel" or policy["--dir"] not in {"in","out"} or not policy["--reqid"].isdigit():
            raise Unsupported("incomplete/unsupported policy guard")
        atoms.append({"kind":"inboundPolicy" if policy["--dir"]=="in" else "outboundPolicy","value":int(policy["--reqid"])})
    elif "policy" in modules:
        raise Unsupported("policy module lacks constraints")
    action=rule["action"]
    if action not in {"accept","drop","reject"}:
        raise Unsupported("unsupported verdict")
    return {"atoms":atoms,"verdict":"allow" if action=="accept" else "deny","ordinal":rule["ordinal"],"raw_text":rule["raw_text"]}
