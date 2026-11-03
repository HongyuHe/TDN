"""Validate complete operational inputs for mixed IPsec, MACsec and L2TP paths."""
import json
from pathlib import Path
import re
import shlex

from .public_manifest import validate_files
from .family import encode_address, parse_hooks, address_range
from .execution import policy_blocks, state_blocks
from .snapshot import require

COMMANDS = {
    "interfaces": ["ip", "-j", "-d", "address"],
    "links": ["ip", "-s", "-j", "-d", "link", "show"],
    "namespace": ["readlink", "/proc/self/ns/net"],
    "named_namespaces": ["ip", "-j", "netns", "list"],
    "peer_nsids": ["ip", "-j", "netns", "list-id"],
    "rules4": ["ip", "-j", "-4", "rule", "show"],
    "rules6": ["ip", "-j", "-6", "rule", "show"],
    "routes4": ["ip", "-j", "-4", "route", "show", "table", "all"],
    "routes6": ["ip", "-j", "-6", "route", "show", "table", "all"],
    "filters4": ["iptables-save", "-c"], "filters6": ["ip6tables-save", "-c"],
    "policies": ["ip", "-s", "xfrm", "policy"],
    "xfrm": ["ip", "-s", "xfrm", "state", "list", "nokeys"],
    "macsec": ["ip", "-s", "macsec", "show"],
    "bridge_links": ["bridge", "-j", "-d", "link", "show"],
    "bridge_vlans": ["bridge", "-j", "-d", "vlan", "show"],
    "bridge_fdb": ["bridge", "-j", "-d", "fdb", "show"],
    "nft_ruleset": ["nft", "-j", "list", "ruleset"],
    "ebtables": ["ebtables-save"],
    "l2tp_tunnels": ["ip", "l2tp", "show", "tunnel"],
    "l2tp_sessions": ["ip", "l2tp", "show", "session"],
    "tunnels4": ["ip", "-d", "tunnel", "show"],
    "tunnels6": ["ip", "-6", "-d", "tunnel", "show"],
    "bridge_netfilter": ["sh", "-c", 'for f in /proc/sys/net/bridge/* /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding; do test -f "$f" && printf \'%s=\' "$f" && cat "$f"; done'],
    "tc": ["sh", "-c", 'for p in /sys/class/net/*; do d=' + chr(36) + '{p##*/}; echo interface=$d; tc -j -s qdisc show dev "$d"; tc -j -s filter show dev "$d" ingress; tc -j -s filter show dev "$d" egress; done']
}


def stable_interface(row):
    info = row.get("linkinfo", {})
    fields = ["ifindex", "ifname", "link_index", "link", "link_netnsid", "master",
              "mtu", "flags", "link_type", "address"]
    data = dict(info.get("info_data", {}))
    for key in list(data):
        if key.endswith("_timer") or key in ["topology_change", "topology_change_detected"]:
            data.pop(key)
    return {key: row.get(key) for key in fields} | {
        "kind": info.get("info_kind"), "data": data,
        "addresses": [(a["family"], a["local"], a["prefixlen"]) for a in row.get("addr_info", [])]}


def check_extra_operations(rows):
    lines = rows["tc"]["value"].splitlines()
    require(len(lines) % 4 == 0, "Incomplete TC inventory")
    for i in range(0, len(lines), 4):
        require(lines[i].startswith("interface="), "Unbound TC interface")
        require(json.loads(lines[i + 2]) == json.loads(lines[i + 3]) == [],
                "TC filters or redirects require additional semantics")
        require(all(q["kind"] in ["noqueue", "fq_codel"] for q in json.loads(lines[i + 1])),
                "Unsupported queue transformation")
    for item in json.loads(rows["nft_ruleset"]["value"])["nftables"]:
        require(len(item) == 1, "Ambiguous nft object")
        kind, value = next(iter(item.items()))
        require(kind in ["metainfo", "table", "chain", "rule"], "Unknown nft operation")
        if kind == "chain":
            require(value.get("type", "filter") == "filter", "Non-filter nft chain")
        if kind == "rule":
            require(all((len(expr) == 1 and next(iter(expr)) in
                        ["match", "counter", "accept", "drop", "reject"]) or
                        expr in [{"xt": {"type": "match", "name": name}} for name in ["policy", "bpf", "multiport", "length"]] for expr in value["expr"]),
                    "nft packet transformation")
    for line in rows["ebtables"]["value"].splitlines():
        if not line or line.startswith("#"):
            continue
        if line in ["*filter", ":INPUT ACCEPT", ":INPUT DROP", ":FORWARD DROP", ":OUTPUT ACCEPT", ":OUTPUT DROP"]:
            continue
        tokens = shlex.split(line)
        require(tokens[:2] == ["-A", "FORWARD"] and tokens[-2:] in
                [["-j", "ACCEPT"], ["-j", "DROP"]], "Unsupported bridge operation")
        matches = tokens[2:-2]
        require(len(matches) % 2 == 0 and all(matches[i] in ["-p", "-s", "-d", "-i", "-o"]
                for i in range(0, len(matches), 2)), "Unsupported bridge match")
    require(rows["tunnels6"]["value"].strip() == "", "Active IPv6 tunnel inventory")
    require(rows["tunnels4"]["value"].strip() in
            ["", "gre0: gre/ip remote any local any ttl inherit nopmtudisc"],
            "Unsupported additional tunnel")



def parse_bridge_filter(text):
    rules = []
    fallback = "allow"
    for line in text.splitlines():
        if line.startswith(":FORWARD "):
            fallback = "allow" if line.split()[1] == "ACCEPT" else "deny"
        if not line.startswith("-A FORWARD "):
            continue
        tokens = shlex.split(line)
        atoms = []
        for i in range(2, len(tokens) - 2, 2):
            option, value = tokens[i:i+2]
            if option in ["-s", "-d"]:
                require(re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", value),
                        "Unsupported bridge MAC mask")
                number = int(value.replace(":", ""), 16)
                atoms.append({"kind": "sourceRange" if option == "-s" else "destinationRange",
                              "low": number, "high": number})
            elif option in ["-i", "-o"]:
                atoms.append({"kind": "ingress" if option == "-i" else "egress", "value": value})
            elif option == "-p":
                protocols = {"MACSEC": 0x88e5, "802_1Q": 0x8100, "S-TAG": 0x88a8}
                number = protocols[value] if value in protocols else int(value, 0)
                atoms.append({"kind": "protocol", "value": str(number)})
            else:
                raise ValueError("Unsupported bridge rule option")
        rules.append({"atoms": atoms, "verdict": "allow" if tokens[-1] == "ACCEPT" else "deny"})
    rules.append({"atoms": [], "verdict": fallback})
    return rules

def parse_mac(device, row, text, tag=None):
    settings = row["linkinfo"]["info_data"]
    require(settings["protect"] and settings["encrypt"] and settings["validation"] == "strict",
            "MACsec lacks full controlled-port protection")
    require(settings["cipher_suite"] == "GCM-AES-256" and settings["icv_len"] == 16 and
            settings["offload"] == "off" and settings["inc_sci"] and
            settings["replay_protect"] and settings["window"] == 0,
            "MACsec mode requires additional implementation scope")
    tx = re.findall(r"TXSC: ([0-9a-f]+) on SA (\d+)", text)
    rx = re.findall(r"RXSC: ([0-9a-f]+), state on", text)
    active = re.findall(r"^\s+(\d+): PN (\d+), state on, key ([0-9a-f]+)$", text, re.M)
    require(len(tx) == len(rx) == 1 and len(active) == 2, "Incomplete or ambiguous MACsec SAs")
    require(tx[0] == (settings["sci"], str(settings["encoding_sa"])), "MACsec settings/SA mismatch")
    require(active[0][0] == tx[0][1], "Active transmit association differs")
    return {"device": device, "logical": row["ifname"], "physical": row["link"],
            "tx_sci": int(tx[0][0], 16), "tx_an": int(tx[0][1]), "tx_pn": int(active[0][1]),
            "rx_sci": int(rx[0], 16), "rx_an": int(active[1][0]), "rx_pn": int(active[1][1]),
            "settings": settings, "tag": tag if tag is not None else (1 if device.startswith("I") else 2),
            "tx_key_id": active[0][2], "rx_key_id": active[1][2],
            "key_generation_contract": "Fixed installed SCI/AN association; receive relation deliberately overapproximates cryptographic acceptance and compares only SCI/AN. Local generation and printed Linux key IDs are not wire fields. Collector provisions matching peer keys for useful controls."}


def parse_carrier(device, rows):
    tunnel = rows["l2tp_tunnels"]["value"]
    session = rows["l2tp_sessions"]["value"]
    if not tunnel.strip():
        require(not session.strip(), "Session without tunnel")
        return None
    t = re.fullmatch(r"Tunnel (\d+), encap UDP\n  From (\S+) to (\S+)\n  Peer tunnel (\d+)\n"
                     r"  UDP source / dest ports: (\d+)/(\d+)\n  UDP checksum: disabled\n", tunnel)
    s = re.fullmatch(r"Session (\d+) in tunnel (\d+)\n  Peer session (\d+), tunnel (\d+)\n"
                     r"  interface name: (\S+)\n  offset 0, peer offset 0\n\n", session)
    require(t and s and t[1] == s[2] and t[4] == s[4], "Unsupported or inconsistent L2TP binding")
    return {"device": device, "interface": s[5], "source": t[2], "destination": t[3],
            "source_port": int(t[5]), "destination_port": int(t[6]),
            "tunnel": int(t[1]), "peer_tunnel": int(t[4]),
            "local_session": int(s[1]), "peer_session": int(s[3])}


def detailed_policies(text, tag):
    normalized = []
    for block in re.split(r"(?m)(?=^src )", text):
        if not block.strip():
            continue
        pattern = (r"src (\S+) dst (\S+) uid 0\s+"
                   r"dir (in|out|fwd) action allow index \d+ priority (\d+) share any flag\s+\(0x00000000\)\s+"
                   r"lifetime config:\s+limit: soft \(INF\)\(bytes\), hard \(INF\)\(bytes\)\s+"
                   r"limit: soft \(INF\)\(packets\), hard \(INF\)\(packets\)\s+"
                   r"expire add: soft 0\(sec\), hard 0\(sec\)\s+"
                   r"expire use: soft 0\(sec\), hard 0\(sec\)\s+"
                   r"lifetime current:\s+\d+\(bytes\), \d+\(packets\)\s+"
                   r"add [0-9 :\-]+ use [0-9 :\-]+\s+"
                   r"tmpl src (\S+) dst (\S+)\s+proto esp spi (0x[0-9a-f]+)\((\d+)\) "
                   r"reqid (\d+)\((0x[0-9a-f]+)\) mode tunnel\s+"
                   r"level required share any\s+enc-mask ffffffff auth-mask ffffffff comp-mask ffffffff\s*")
        match = re.fullmatch(pattern, block)
        require(match is not None, "Unsupported detailed SPD operation")
        source, destination, direction, priority, sender, receiver, spi, spi_decimal, reqid, reqid_hex = match.groups()
        require(int(spi, 16) == int(spi_decimal) and int(reqid) == int(reqid_hex, 16),
                "Inconsistent printed SPI/reqid")
        spi_field = "" if int(spi, 16) == 0 else "spi " + spi + " "
        normalized.append("src " + source + " dst " + destination +
                          "\n dir " + direction + " priority " + priority +
                          "\n tmpl src " + sender + " dst " + receiver +
                          "\n proto esp " + spi_field + "reqid " + reqid + " mode tunnel\n")
    return policy_blocks("".join(normalized), tag, encode_address)


def parse(path):
    digest = validate_files(path)
    evidence = json.loads((path / "evidence.json").read_text())
    require(evidence["error"] is None, "Failed pairing experiment")
    commands = json.loads((path / "commands.json").read_text())
    indexed = {r["id"]: r for r in commands}
    require(len(indexed) == len(commands), "Duplicate command")
    devices = {d["id"]: d for d in evidence["devices"]}
    phase_names = (["bridged-before.json", "bridged-after.json"] if (path / "bridged-before.json").exists()
                   else ["stable-before.json", "stable-after.json"])
    if (path / "sizing.json").exists():
        from ..mixed_sizing import parse as validate_sizing
        validate_sizing(path)
        phase_names = ["sizing-after.json", "stable-after.json"]
    phases = [json.loads((path / name).read_text()) for name in phase_names]
    phase_reports = []
    for phase in phases:
        require(set(phase) == set(devices), "Incomplete device inventory")
        require(len({phase[n]["namespace"]["value"] for n in devices}) == len(devices),
                "Device namespaces overlap")
        interfaces, links, bridges, macs, carriers, policies, states, hooks = {}, [], [], [], [], {}, {}, {}
        bridge_filters = {}
        routes = []
        for name, rows in phase.items():
            expected = COMMANDS | {"namespace_inode": ["stat", "-Lc", "%i", "/var/run/netns/" + devices[name]["namespace"]]}
            require(set(rows) == set(expected), "Incomplete operational inventory")
            for kind, observed in rows.items():
                raw = indexed[observed["observation_id"]]
                require(raw["command"] == ["ip", "netns", "exec", devices[name]["namespace"]] + expected[kind] and
                        raw["device_id"] == name and raw["stdout"] == observed["value"] and
                        raw["returncode"] == observed["returncode"] == 0, "Raw operational binding differs")
            require(rows["namespace"]["value"].strip() == "net:[" + rows["namespace_inode"]["value"].strip() + "]",
                    "Namespace inode differs")
            named = json.loads(rows["named_namespaces"]["value"])
            peers = json.loads(rows["peer_nsids"]["value"])
            require(len({r["name"] for r in named}) == len(named), "Duplicate named namespace")
            require(len({r["nsid"] for r in peers}) == len(peers), "Duplicate peer namespace ID")
            require({d["namespace"] for d in devices.values()} <= {r["name"] for r in named},
                    "Missing declared namespace")
            check_extra_operations(rows)
            bridge_filters[name] = parse_bridge_filter(rows["ebtables"]["value"])
            addresses = json.loads(rows["interfaces"]["value"])
            tc_names = [line.split("=", 1)[1] for line in rows["tc"]["value"].splitlines()
                        if line.startswith("interface=")]
            require(set(tc_names) == {r["ifname"] for r in addresses} and
                    len(tc_names) == len(set(tc_names)), "TC inventory omits an interface")
            link_rows = json.loads(rows["links"]["value"])
            require({r["ifname"] for r in addresses} == {r["ifname"] for r in link_rows},
                    "Address/link interface inventory differs")
            for interface in addresses:
                corresponding = [r for r in link_rows if r["ifname"] == interface["ifname"]]
                require(len(corresponding) == 1 and corresponding[0]["ifindex"] == interface["ifindex"],
                        "Link identity differs")
                first = stable_interface(interface)
                second = stable_interface(corresponding[0])
                require({k: v for k, v in first.items() if k != "addresses"} ==
                        {k: v for k, v in second.items() if k != "addresses"},
                        "Detailed link configuration differs from address capture")
                if "UP" not in interface["flags"]:
                    continue
                key = name + ":" + interface["ifname"]
                require(key not in interfaces, "Duplicate active interface")
                interfaces[key] = interface
                kind = interface.get("linkinfo", {}).get("info_kind")
                require(kind in ["veth", "macsec", "bridge"] or interface["ifname"] == "lo" or
                        interface["ifname"].startswith("l2tpeth"), "Unmodeled active interface")
                if kind == "macsec":
                    require(devices[name]["role"] in ["inner", "outer"], "MACsec device has no encryption-layer role")
                    macs.append(parse_mac(name, interface, rows["macsec"]["value"],
                        1 if devices[name]["role"] == "inner" else 2))
                if kind == "bridge":
                    require(interface["linkinfo"]["info_data"]["vlan_filtering"] == 0,
                            "VLAN filtering needs a separate bridge model")
            members = [(name + ":" + r["ifname"], r["master"]) for r in addresses if r.get("master")]
            observed_bridge = json.loads(rows["bridge_links"]["value"])
            require(set(members) == {(name + ":" + r["ifname"], r["master"]) for r in observed_bridge},
                    "Bridge membership inventory differs")
            for first, master in members:
                for second, other in members:
                    if first != second and master == other:
                        bridges.append([first, second])
            for first, master in members:
                bridges.extend([[first, name + ":" + master], [name + ":" + master, first]])
            carrier = parse_carrier(name, rows)
            if carrier:
                require(name + ":" + carrier["interface"] in interfaces, "Carrier interface absent")
                carriers.append(carrier)
            missing_kind = [r["ifname"] for r in addresses if "UP" in r["flags"] and
                            r["ifname"] != "lo" and not r.get("linkinfo", {}).get("info_kind")]
            require(missing_kind == ([carrier["interface"]] if carrier else []),
                    "Unknown active nonstandard interface")
            if not any(r["device"] == name for r in macs):
                require(not rows["macsec"]["value"].strip(), "MACsec state without interface")
            tag = 1 if devices[name]["role"] == "inner" else 2
            policies[name] = detailed_policies(rows["policies"]["value"], tag)
            states[name] = state_blocks(rows["xfrm"]["value"], encode_address)
            hooks[name] = {}
            for family in [4, 6]:
                routing_rules = json.loads(rows["rules" + str(family)]["value"])
                priorities = {}
                for rule in routing_rules:
                    require(set(rule) <= {"priority", "src", "table", "protocol"} and
                            rule.get("src") == "all", "Unsupported policy-routing selector")
                    require(str(rule["table"]) not in priorities, "Repeated policy-routing table")
                    priorities[str(rule["table"])] = int(rule.get("priority", 0))
                for route in json.loads(rows["routes" + str(family)]["value"]):
                    kind = route.get("type", "unicast")
                    require(kind in ["unicast", "multicast", "local", "broadcast", "anycast"],
                            "Unknown route disposition")
                    require(not any(k in route for k in ["multipath", "encap", "nhid"]),
                            "Unmodeled route operation")
                    if kind in ["local", "broadcast", "anycast"]:
                        continue
                    require(name + ":" + route["dev"] in interfaces, "Route to missing active interface")
                    low, high, prefix = address_range(route["dst"], family)
                    table = str(route.get("table", "main"))
                    require(table in priorities, "Unbound route table")
                    routes.append({"device": name, "egress": name + ":" + route["dev"],
                                   "low": low, "high": high, "prefix": prefix,
                                   "metric": int(route.get("metric", 0)), "priority": priorities[table],
                                   "gateway": encode_address(route["gateway"]) if "gateway" in route else None})
                raw = re.sub(r"(?m)^\[\d+:\d+\] ", "", rows["filters" + str(family)]["value"])
                hooks[name][family] = parse_hooks(raw, family)
        for key, interface in interfaces.items():
            if interface.get("linkinfo", {}).get("info_kind") != "veth":
                continue
            name = key.split(":")[0]
            peer_rows = json.loads(phase[name]["peer_nsids"]["value"])
            peer = [r.get("name") for r in peer_rows if r["nsid"] == interface["link_netnsid"]]
            require(len(peer) == 1 and peer[0] in [d["namespace"] for d in devices.values()],
                    "Veth peer namespace is unknown or ambiguous")
            named = json.loads(phase[name]["named_namespaces"]["value"])
            require([r["name"] for r in named if r.get("id") == interface["link_netnsid"]] == peer,
                    "Named namespace and peer NSID disagree")
            target = next(n for n, d in devices.items() if d["namespace"] == peer[0])
            matches = [k for k, row in interfaces.items() if k.startswith(target + ":") and
                       row["ifindex"] == interface["link_index"] and row.get("link_index") == interface["ifindex"]]
            require(len(matches) == 1, "Reciprocal namespace-bound veth missing")
            links.append([key, matches[0]])
        for mac in macs:
            require(mac["device"] + ":" + mac["physical"] in interfaces, "Missing MACsec lower interface")
            require(len([peer for peer in macs if peer["tx_sci"] == mac["rx_sci"] and
                         peer["tx_an"] == mac["rx_an"] and peer["tag"] == mac["tag"]]) == 1,
                    "MACsec receive association has no unique peer/tag binding")
        for carrier in carriers:
            require(len([peer for peer in carriers if peer["source"] == carrier["destination"] and
                         peer["destination"] == carrier["source"] and
                         peer["local_session"] == carrier["peer_session"] and
                         peer["peer_session"] == carrier["local_session"]]) == 1, "L2TP peer/session mismatch")
        phase_reports.append({"interfaces": {k: stable_interface(v) for k, v in interfaces.items()},
                              "links": links, "bridges": bridges, "bridge_filters": bridge_filters, "mac_ports": macs, "carriers": carriers,
                              "policies": policies, "states": states, "hooks": hooks, "routes": routes,
                              "namespace_bindings": {n: phase[n]["namespace"]["value"] for n in devices}})
    declared_links = {frozenset(link["endpoints"]) for link in evidence["links"]}
    require(all(link["relation"] == "veth" for link in evidence["links"]),
            "Unmodeled declared physical relation")
    require(declared_links == {frozenset(link) for link in phase_reports[0]["links"]},
            "Declared zones omit or add a physical link")
    before, after = phase_reports
    address_epochs = {}
    require(set(before["interfaces"]) == set(after["interfaces"]), "Active interface inventory changed")
    for key, first in before["interfaces"].items():
        second = after["interfaces"][key]
        require({k: v for k, v in first.items() if k != "addresses"} ==
                {k: v for k, v in second.items() if k != "addresses"}, "Interface identity/configuration changed")
        if first["addresses"] != second["addresses"]:
            address_epochs[key] = {"before": first["addresses"], "after": second["addresses"]}
            first["addresses"] = sorted(set(first["addresses"]) | set(second["addresses"]))
    route_epochs = None
    before_routes = sorted(before["routes"], key=lambda r: json.dumps(r, sort_keys=True))
    after_routes = sorted(after["routes"], key=lambda r: json.dumps(r, sort_keys=True))
    if before_routes != after_routes:
        route_epochs = {"before": before_routes, "after": after_routes}
        changed = [r for r in before_routes + after_routes if
                   (r not in before_routes or r not in after_routes)]
        require(all(r in after_routes for r in before_routes), "Captured route removal/change")
        for route in changed:
            require(route["gateway"] is None and route["prefix"] == 64 and
                    route["low"] == encode_address("fe80::") and
                    route["high"] == encode_address("fe80::ffff:ffff:ffff:ffff"),
                    "Only automatic equal-ranked link-local route additions use epoch union")
            for other in before_routes + after_routes:
                overlap = (route["device"] == other["device"] and
                           max(route["low"], other["low"]) <= min(route["high"], other["high"]))
                if overlap:
                    require(all(route[k] == other[k] for k in ["prefix", "metric", "priority"]),
                            "Changed route preference cannot use a simple epoch union")
        before["routes"] = before_routes + [r for r in after_routes if r not in before_routes]
    for key in ["links", "bridges", "bridge_filters", "carriers", "policies", "states", "hooks", "namespace_bindings"]:
        require(before[key] == after[key], "Operational state changed: " + key)
    def static_mac(rows):
        return [{k: v for k, v in row.items() if k not in ["tx_pn", "rx_pn"]} for row in rows]
    require(static_mac(before["mac_ports"]) == static_mac(after["mac_ports"]), "MACsec configuration changed")
    require(len(evidence["probes"]) in [4, 6, 20] and all(p["observed_result"] == p["expected_result"]
            for p in evidence["probes"]), "Expected useful/loss/restoration probes differ")
    return {"bundle": str(path), "manifest_sha256": digest, "devices": devices, "operational": before, "architecture_links": evidence["links"],
            "phase_files": phase_names, "address_epochs": address_epochs, "route_epochs": route_epochs, "scope": "Validated mixed-mechanism operational inputs. Local addresses and equal-ranked route alternatives include every before/after observation; changed address epochs are retained explicitly and do not assert atomic simultaneity. Network invariant and positive Lean executions remain under construction. Bridge filtering/queues are safety overapproximations; the source inventories exclude redirects and transformations."}


