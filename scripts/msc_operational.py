"""Parse retained operational observations into deployment-independent records."""

import ipaddress
import json
import re


def ipv4(value):
    return int(ipaddress.IPv4Address(value))


def cidr(value):
    if value in {"all", "default"}:
        value = "0.0.0.0/0"
    address = ipaddress.IPv4Interface(value)
    return {"address": int(address.ip), "length": address.network.prefixlen}


def table_number(value):
    names = {"local": 255, "main": 254, "default": 253}
    return names[value] if value in names else int(value)


def parse_interfaces(text, management_ports):
    rows = json.loads(text)
    if not isinstance(rows, list):
        raise ValueError("interfaces must be an observed JSON array")
    result = []
    for row in rows:
        if row["ifname"] in management_ports:
            continue
        if row.get("link_type") not in {"ether", "loopback"}:
            raise ValueError("unsupported interface link type")
        ipv4_rows = [a for a in row["addr_info"] if a["family"] == "inet"]
        metadata = []
        for address in ipv4_rows:
            if not all(key in address for key in ["valid_life_time", "preferred_life_time"]):
                metadata = None
                break
            if (type(address.get("dynamic", False)) is not bool or
                    any(type(address[key]) is not int or address[key] < 0
                        for key in ["valid_life_time", "preferred_life_time"])):
                raise ValueError("unsupported address lifetime or dynamic flag")
            metadata.append({"network": cidr(f'{address["local"]}/{address["prefixlen"]}'),
                             "dynamic": address.get("dynamic", False),
                             "validLifetime": address["valid_life_time"],
                             "preferredLifetime": address["preferred_life_time"]})
        result.append({"name": row["ifname"], "index": row["ifindex"],
                       "peerIndex": row.get("link_index"), "mtu": row["mtu"],
                       "up": "UP" in row["flags"], "carrier": "LOWER_UP" in row["flags"],
                       "mac": row["address"], "master": row.get("master", ""),
                       "addresses": [cidr(f'{a["local"]}/{a["prefixlen"]}') for a in ipv4_rows],
                       "addressMetadata": metadata})
    return result


def parse_routes(text, management_ports):
    result = []
    allowed = {"dst", "gateway", "dev", "table", "type", "protocol", "metric", "scope", "prefsrc", "flags", "nhid"}
    for row in json.loads(text):
        if row.get("dev") in management_ports:
            continue
        if row.keys() - allowed or row.get("flags", []):
            raise ValueError("unsupported routing attributes or flags")
        if row.get("type", "unicast") not in {"unicast", "local", "broadcast"}:
            raise ValueError("unsupported routing action")
        scope = row.get("scope", "global")
        if scope not in {"global", "link", "host"}:
            raise ValueError("unsupported routing scope")
        if not row.get("dev"):
            raise ValueError("route lacks an expanded output interface")
        if "nhid" in row and (not isinstance(row["nhid"], int) or isinstance(row["nhid"], bool)
                              or row["nhid"] <= 0 or "gateway" not in row):
            raise ValueError("unsupported or unexpanded next-hop object")
        result.append({"destination": cidr(row["dst"]),
                       "gateway": ipv4(row["gateway"]) if "gateway" in row else None,
                       "output": row.get("dev", ""), "table": table_number(row.get("table", "main")),
                       "kind": row.get("type", "unicast"), "protocol": str(row.get("protocol", "")),
                       "metric": row.get("metric", 0),
                       "preferredSource": ipv4(row["prefsrc"]) if "prefsrc" in row else None,
                       "scope": scope, "nextHopId": row.get("nhid")})
    return result


def parse_rules(text):
    result = []
    for row in json.loads(text):
        if set(row) != {"priority", "src", "table"}:
            raise ValueError("unsupported policy-routing rule")
        result.append({"priority": row["priority"], "source": cidr(row["src"]), "table": table_number(row["table"])})
    return result


def blocks(text):
    return [b.strip() for b in re.split(r"(?m)(?=^src )", text) if b.strip()]


def parse_policies(text):
    result = []
    for block in blocks(text):
        if "\tsocket " in block:
            #* Socket-wide defaults apply to locally generated socket traffic.
            #* Preserve the supported boundary by rejecting restricted socket policies.
            if not re.fullmatch(r"src (0\.0\.0\.0/0|::/0) dst \1\s+socket (in|out) priority 0", block):
                raise ValueError("unsupported socket XFRM policy")
            continue
        match = re.fullmatch(
            r"src (\S+) dst (\S+)\s+dir (in|out|fwd) priority (\d+)\s+"
            r"tmpl src (\S+) dst (\S+)\s+proto (esp|ah)(?: spi (0x[0-9a-f]+))? reqid (\d+) mode (tunnel|transport)", block)
        if not match:
            raise ValueError("unsupported XFRM policy: " + block[:120])
        source, target, direction, priority, local, remote, protocol, spi, reqid, mode = match.groups()
        result.append({"source": cidr(source), "destination": cidr(target), "direction": direction,
                       "priority": int(priority), "tunnelSource": ipv4(local), "tunnelDestination": ipv4(remote),
                       "reqid": int(reqid), "mode": mode, "protocol": protocol,
                       "spi": int(spi, 16) if spi else 0})
    return result


def validate_state_shape(block):
    #* Every retained state line has an explicit supported interpretation.
    #* Counters and timestamps remain in raw evidence but do not change the
    #* fixed-state packet relation. Unknown or repeated fields are rejected.
    stamp = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
    patterns = [
        r"src \S+ dst \S+",
        r"proto (?:esp|ah) spi 0x[0-9a-f]+(?:\(\d+\))? reqid \d+(?:\(0x[0-9a-f]+\))? mode (?:tunnel|transport)",
        r"replay-window \d+ seq 0x[0-9a-f]+ flag .*",
        r"aead \S+ <<Keys hidden>> \d+",
        r"lastused " + stamp,
        r"anti-replay context: seq 0x[0-9a-f]+, oseq 0x[0-9a-f]+, bitmap 0x[0-9a-f]+",
        r"lifetime config:",
        r"limit: soft \(INF\)\(bytes\), hard \(INF\)\(bytes\)",
        r"limit: soft \(INF\)\(packets\), hard \(INF\)\(packets\)",
        r"expire add: soft \d+\(sec\), hard \d+\(sec\)",
        r"expire use: soft 0\(sec\), hard 0\(sec\)",
        r"lifetime current:",
        r"\d+\(bytes\), \d+\(packets\)",
        r"add " + stamp + r" use (?:" + stamp + r"|-)",
        r"stats:",
        r"replay-window \d+ replay \d+ failed \d+",
        r"encap type espinudp sport \d+ dport \d+ addr \S+",
        r"tfcpad \d+",
    ]
    seen = set()
    for line in block.splitlines():
        line = line.strip()
        matched = [index for index, pattern in enumerate(patterns) if re.fullmatch(pattern, line)]
        if len(matched) != 1 or matched[0] in seen:
            raise ValueError("unsupported or duplicate XFRM state field: " + line[:100])
        seen.add(matched[0])


def parse_states(text):
    result = []
    for block in blocks(text):
        validate_state_shape(block)
        header = re.match(r"src (\S+) dst (\S+)\s+proto (esp|ah) spi (0x[0-9a-f]+)(?:\(\d+\))? reqid (\d+)(?:\(0x[0-9a-f]+\))? mode (tunnel|transport)\n", block)
        aead = re.search(r"(?m)^\s*aead (\S+) <<Keys hidden>> (\d+)\s*$", block)
        replay = re.search(r"(?m)^\s*replay-window (\d+) seq 0x[0-9a-f]+ flag ([^\n]*?)\s*\(0x([01]{8})\)\s*$", block)
        life = re.search(r"expire add: soft \d+\(sec\), hard (\d+)\(sec\)", block)
        if not all([header, aead, replay, life]):
            raise ValueError("incomplete or unsupported redacted XFRM state")
        #* iproute2 strxf_mask8 prints a binary bit string despite its 0x prefix.
        #* All unmodeled named flags and extra flags remain explicit errors.
        flags = int(replay[3], 2)
        if (flags, replay[2].strip()) not in {(0, ""), (32, "af-unspec")}:
            raise ValueError("unsupported XFRM state flags")
        if re.search(r"(?m)^\s*(mark|output-mark|if_id|sel|auth|enc|comp) ", block):
            raise ValueError("unsupported XFRM state semantics")
        encap = re.search(r"(?m)^\s*encap type espinudp sport (\d+) dport (\d+) addr (\S+)\s*$", block)
        if "encap " in block and not encap:
            raise ValueError("unsupported XFRM encapsulation")
        tfc = re.search(r"(?m)^\s*tfcpad (\d+)\s*$", block)
        source, target, protocol, spi, reqid, mode = header.groups()
        result.append({"source": ipv4(source), "destination": ipv4(target), "spi": int(spi, 16),
                       "reqid": int(reqid), "mode": mode, "protocol": protocol,
                       "algorithm": aead[1], "integrityBits": int(aead[2]), "replayWindow": int(replay[1]),
                       "hardLifetimeSeconds": int(life[1]), "udpEncapsulation": encap is not None,
                       "udpSourcePort": int(encap[1]) if encap else None,
                       "udpDestinationPort": int(encap[2]) if encap else None,
                       "tfcPadding": int(tfc[1]) if tfc else 0, "flags": flags,
                       "udpOriginalAddress": ipv4(encap[3]) if encap else None})
    return result


def parse_switch(facts, management_ports):
    ovs = facts["ovs"]
    ports = json.loads(facts["ovs-ports"])
    if set(ports["headings"]) != {"name", "tag", "trunks", "vlan_mode"}:
        raise ValueError("unsupported switch port inventory")
    rows = [dict(zip(ports["headings"], r)) for r in ports["data"]]
    rows = [r for r in rows if r["name"] not in management_ports]
    bridges = re.findall(r"(?m)^\s*Bridge (\S+)\s*$", ovs)
    modes = re.findall(r"(?m)^\s*fail_mode: (\S+)\s*$", ovs)
    if len(bridges) != 1 or len(modes) != 1:
        raise ValueError("ambiguous switch bridge or fail mode")
    flows = [line for line in facts["openflow"].splitlines() if "actions=" in line]
    normal = len(flows) == 1 and "table=0," in flows[0] and bool(re.search(r"priority=0\s+actions=NORMAL\s*$", flows[0]))
    return {"ports": sorted(r["name"] for r in rows if r["name"] != bridges[0]),
            "bridge": bridges[0], "failMode": modes[0],
            "controllers": re.findall(r"(?m)^\s*Controller (.+)$", ovs), "normalOnly": normal,
            "vlanConfigured": any(r[k] != ["set", []] for r in rows for k in ["tag", "trunks", "vlan_mode"])}


def parse_resolver(text):
    servers = []
    for line in text.splitlines():
        tokens = line.split("#", 1)[0].split()
        if tokens and tokens[0] == "nameserver":
            if len(tokens) != 2:
                raise ValueError("invalid resolver nameserver directive")
            servers.append(ipv4(tokens[1]))
    return servers


def parse_operational(observation, management_ports):
    facts, errors = observation["facts"], observation.get("errors", {})

    def read(key, parser):
        if key not in facts or key in errors:
            return None
        return parser(facts[key])

    def forwarding(text):
        if text.strip() not in {"0", "1"}:
            raise ValueError("invalid IPv4 forwarding observation")
        return text.strip() == "1"

    switching = None
    if all(key in facts and key not in errors for key in ["ovs", "ovs-ports", "openflow"]):
        switching = parse_switch(facts, management_ports)
    return {"device": observation["device"], "observedAt": observation["observed_at"],
            "interfaces": read("interfaces", lambda t: parse_interfaces(t, management_ports)),
            "routes": read("routes", lambda t: parse_routes(t, management_ports)),
            "routingRules": read("rules", parse_rules), "forwarding": read("forwarding", forwarding),
            "policies": read("policies", parse_policies), "states": read("xfrm", parse_states),
            "switching": switching, "clockEpoch": read("clock-epoch", lambda t: int(t.strip())),
            "resolverServers": read("resolver", parse_resolver),
            "processes": read("processes", lambda t: t.split()), "startup": read("startup", str.strip)}


def render_operational(value, record, sequence, optional, quoted):
    def render(v):
        if isinstance(v, bool):
            return str(v).lower()
        if isinstance(v, str):
            return quoted(v)
        if isinstance(v, int):
            return str(v)
        if isinstance(v, list):
            return sequence(render(x) for x in v)
        if isinstance(v, dict):
            return record(**{k: optional(x, render) if k in {"peerIndex", "gateway", "preferredSource", "nextHopId", "udpSourcePort", "udpDestinationPort", "udpOriginalAddress", "addressMetadata"} else render(x)
                             for k, x in v.items()})
        raise ValueError("unsupported operational value")

    return record(**{key: quoted(value[key]) if key in {"device", "observedAt"} else optional(value[key], render)
                     for key in value})
