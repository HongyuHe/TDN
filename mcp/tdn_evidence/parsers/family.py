"""Interpret family-tagged addresses and ordered firewall hooks."""
import ipaddress
import re
import shlex
from .snapshot import require
from .packet_policy import parse_rule


IPV6_OFFSET = 2 ** 128


def encode_address(value):
    address = ipaddress.ip_address(value)
    return int(address) + (IPV6_OFFSET if address.version == 6 else 0)


def family_range(family):
    return (0, 2 ** 32 - 1) if family == 4 else (IPV6_OFFSET, 2 * IPV6_OFFSET - 1)


def address_range(prefix, family):
    network = ipaddress.ip_network(("0.0.0.0/0" if family == 4 else "::/0") if prefix == "default" else prefix, strict=False)
    require(network.version == family, "Route address family mismatch")
    return encode_address(network.network_address), encode_address(network.broadcast_address), network.prefixlen


def split_filter_and_immediate_gate(text):
    tables, table = {}, None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            require(table in ["raw", "filter"] and table not in tables, "Unsupported or repeated table")
            tables[table] = [line]
        else:
            require(table is not None, "Content outside a firewall table")
            tables[table].append(line)
            if line == "COMMIT":
                table = None
    require(table is None, "Incomplete firewall table")
    values = None
    if "raw" in tables:
        lines = [re.sub(r"\[\d+:\d+\]", "[0:0]", line) for line in tables["raw"]]
        require(lines[:6] == ["*raw", ":PREROUTING ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]",
                             ":EVA6_IMMEDIATE - [0:0]", "-A PREROUTING -j EVA6_IMMEDIATE",
                             "-A OUTPUT -j EVA6_IMMEDIATE"], "Unrecognized raw hook/chain structure")
        require(lines[-2:] == ["-A EVA6_IMMEDIATE -j DROP", "COMMIT"], "Missing terminal immediate-header drop")
        values = []
        for line in lines[6:-2]:
            tokens = shlex.split(line)
            require(tokens[:5] == ["-A", "EVA6_IMMEDIATE", "-m", "u32", "--u32"] and
                    tokens[-2:] == ["-j", "RETURN"] and len(tokens) == 8, "Unsupported raw operation")
            expression = re.fullmatch(r"0x4>>0x8&0xff=(0x[0-9a-f]+)", tokens[5])
            require(expression is not None, "Raw expression is not immediate Next Header")
            values.append(int(expression[1], 16))
        require(values and len(values) == len(set(values)), "Empty or duplicate immediate-header alternatives")
    return "\n".join(tables.get("filter", [])), values


def parse_hooks(text, family):
    text, immediate = split_filter_and_immediate_gate(text)
    require(immediate is None or family == 6, "IPv6 raw gate used on IPv4")
    hooks = {name: {"policy": "accept", "ordered_rules": [], "parsed_rules": []}
             for name in ["INPUT", "FORWARD", "OUTPUT"]}
    table = None
    seen = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            require(table == "filter", "Non-filter table requires additional processing semantics")
        elif line == "COMMIT":
            table = None
        elif line.startswith(":"):
            match = re.fullmatch(r":(\S+) (ACCEPT|DROP) \[\d+:\d+\]", line)
            require(match and match[1] in hooks, "Custom chain or unsupported default")
            hooks[match[1]]["policy"] = match[2].lower()
            seen.add(match[1])
        else:
            require(table == "filter", "Rule outside captured filter table")
            tokens = shlex.split(line)
            require(tokens[:1] == ["-A"] and tokens[1] in hooks, "Unsupported hook syntax")
            chain = hooks[tokens[1]]
            require("-j" in tokens, "Missing rule verdict")
            jump = tokens.index("-j")
            require(jump == len(tokens) - 2 and tokens[-1] in ["ACCEPT", "DROP", "REJECT"], "Unsupported filter action")
            matches = tokens[2:jump]
            if "policy" in matches and "--mode" not in matches:
                matches += ["--mode", "tunnel"]
            raw = {"matches": {"iptables_tokens": matches}, "action": tokens[-1].lower(),
                   "ordinal": len(chain["ordered_rules"]), "raw_text": line}
            parsed = parse_rule(raw)
            low, high = family_range(family)
            atoms = [{"kind": "sourceRange", "low": low, "high": high},
                     {"kind": "destinationRange", "low": low, "high": high}]
            for atom in parsed["atoms"]:
                if atom["kind"] in ["sourceRange", "destinationRange"]:
                    require(atom["family"] == family, "Filter prefix has wrong address family")
                    offset = IPV6_OFFSET if family == 6 else 0
                    atom["low"] += offset
                    atom["high"] += offset
                atoms.append(atom)
            parsed["atoms"] = atoms
            chain["ordered_rules"].append(raw)
            chain["parsed_rules"].append(parsed)
    require(not text.strip() or seen == set(hooks), "Incomplete hook/default inventory")
    for chain in hooks.values():
        low, high = family_range(family)
        chain["parsed_rules"].append({"atoms": [
            {"kind": "sourceRange", "low": low, "high": high},
            {"kind": "destinationRange", "low": low, "high": high}],
            "verdict": "allow" if chain["policy"] == "accept" else "deny"})
    return hooks


