"""Import family-tagged IPsec packet execution from supplemental raw namespace captures."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex

from import_execution import association_list, policy_blocks, state_blocks
from import_snapshot import parse_rule, lean_atom, lean_list, quoted
from validate_evidence import require
from execution_codegen import render

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


def render_rules(rules):
    return lean_list(["⟨" + lean_list([lean_atom(atom) for atom in rule["atoms"]]) +
                      ", ." + rule["verdict"] + "⟩" for rule in rules])


def load_bundle(path):
    manifest = json.loads((path / "manifest.json").read_text())
    names = [item["path"] for item in manifest["files"]]
    require(len(names) == len(set(names)), "Duplicate manifest entry")
    actual = {str(file.relative_to(path)) for file in path.rglob("*")
              if file.is_file() and file.name != "manifest.json"}
    require(set(names) == actual, "Manifest omits a family input")
    for item in manifest["files"]:
        file = (path / item["path"]).resolve()
        file.relative_to(path.resolve())
        require(hashlib.sha256(file.read_bytes()).hexdigest() == item["sha256"], "Family bundle hash mismatch")
    require(manifest.get("error") is None, "Family experiment failed")
    evidence = json.loads((path / "evidence.json").read_text())
    commands = json.loads((path / "commands.json").read_text())
    indexed = {record["id"]: record for record in commands}
    require(len(indexed) == len(commands), "Duplicate raw command identity")
    phases = [json.loads((path / name).read_text()) for name in ["stable-before.json", "stable-after.json"]]
    expected = {device["id"] for device in evidence["devices"]}
    namespaces = {device["id"]: device["namespace"] for device in evidence["devices"]}
    required_commands = {
        "interfaces": ["ip", "-j", "-d", "address"],
        "rules4": ["ip", "-j", "-4", "rule", "show"],
        "rules6": ["ip", "-j", "-6", "rule", "show"],
        "namespace": ["readlink", "/proc/self/ns/net"],
        "named_namespaces": ["ip", "-j", "netns", "list"],
        "peer_nsids": ["ip", "-j", "netns", "list-id"],
        "routes4": ["ip", "-j", "-4", "route", "show", "table", "all"],
        "routes6": ["ip", "-j", "-6", "route", "show", "table", "all"],
        "filters4": ["iptables-save"], "filters6": ["ip6tables-save"],
        "policies": ["ip", "xfrm", "policy"],
        "xfrm": ["ip", "-s", "xfrm", "state", "list", "nokeys"],
        "macsec": ["ip", "-s", "macsec", "show"]
    }
    optional_commands = {"neighbors": ["ip", "-j", "neighbor", "show"],
                         "nft": ["nft", "-a", "-j", "list", "ruleset"]}
    for phase in phases:
        require(set(phase) == expected, "Stable capture device inventory mismatch")
        require(len({phase[d]["namespace"]["value"] for d in expected}) == len(expected),
                "Distinct devices share a namespace")
        for device, observations in phase.items():
            require(set(required_commands) <= set(observations) <=
                    set(required_commands) | set(optional_commands),
                    "Incomplete or unknown observation kinds")
            named = json.loads(observations["named_namespaces"]["value"])
            require(set(namespaces.values()) <= {row["name"] for row in named},
                    "Declared device inventory differs from observed namespaces")
            require(len(named) == len({row["name"] for row in named}), "Duplicate named namespace")
            for kind, observed in observations.items():
                raw = indexed[observed["observation_id"]]
                require(raw["command"][:4] == ["ip", "netns", "exec", namespaces[device]],
                        "Raw command namespace differs from device")
                expected_command = (required_commands | optional_commands)[kind]
                require(raw["command"][4:] == expected_command, "Wrong raw command for observation kind")
                require(raw["device_id"] == device and raw["stdout"] == observed["value"] and
                        raw["returncode"] == observed["returncode"] == 0, "Stable export differs from raw command")
    require(set(phases[0]) == set(phases[1]), "Device coverage changed")
    for device in expected:
        require(phases[0][device]["namespace"]["value"] == phases[1][device]["namespace"]["value"],
                "Namespace binding changed")
        for kind in ["named_namespaces", "peer_nsids"]:
            selected = []
            for phase in phases:
                rows = json.loads(phase[device][kind]["value"])
                key = "id" if kind == "named_namespaces" else "nsid"
                identifiers = [row[key] for row in rows if key in row and row[key] >= 0]
                require(len(identifiers) == len(set(identifiers)), "Ambiguous namespace ID")
                selected.append(sorted([row for row in rows if row.get("name") in namespaces.values()],
                                       key=lambda row: row["name"]))
            require(selected[0] == selected[1], "Selected namespace binding changed")
        def structural_interfaces(phase):
            values = json.loads(phase[device]["interfaces"]["value"])
            return [{key: item.get(key) for key in ["ifindex", "link_index", "ifname", "flags", "link_type",
                                                   "linkinfo", "link_netnsid"]} |
                    {"addresses": [(a["family"], a["local"], a["prefixlen"]) for a in item.get("addr_info", [])]}
                    for item in values]
        require(structural_interfaces(phases[0]) == structural_interfaces(phases[1]),
                "Interface, peer or address state changed across collection")
    return evidence, commands, phases


def parse_early_header_gate(path, evidence, commands):
    source = path / "early-header-policy.json"
    if not source.exists():
        return {}
    supplied = json.loads(source.read_text())
    expected = {d["id"]: d["namespace"] for d in evidence["devices"]
                if d["role"] in {"inner", "outer", "inner-encryptor", "outer-encryptor"}}
    require(expected and set(supplied["devices"]) == set(expected) and
            set(supplied["rules"]) == set(expected), "Incomplete early-gate device inventory")
    indexed = {row["id"]: row for row in commands}
    result = {}
    protocol_numbers = {"tcp": 6, "udp": 17, "esp": 50, "ipv6-icmp": 58}
    table_name = "EVA6_BEFORE_DEFRAG"
    for device, namespace in expected.items():
        record = supplied["rules"][device]
        raw = indexed[record["observation_id"]]
        require(raw["command"] == ["ip", "netns", "exec", namespace, "nft", "-a", "-j",
                                   "list", "table", "ip6", table_name] and
                raw["device_id"] == device and raw["returncode"] == 0,
                "Early gate has wrong raw command or namespace")
        actual = json.loads(raw["stdout"])
        require(actual == record["ruleset"], "Early gate differs from complete raw table")
        objects = actual["nftables"]
        require(len(objects) == 6 and [list(item) for item in objects] ==
                [["metainfo"], ["table"], ["chain"], ["chain"], ["rule"], ["rule"]],
                "Unexpected early-table object inventory")
        table = {k: v for k, v in objects[1]["table"].items() if k != "handle"}
        require(table == {"family": "ip6", "name": table_name}, "Wrong early table")
        hooks = {}
        for item in objects[2:4]:
            chain = {k: v for k, v in item["chain"].items() if k != "handle"}
            hook = chain["hook"]
            require(hook in {"prerouting", "output"} and hook not in hooks and chain == {
                "family": "ip6", "table": table_name, "name": hook, "type": "filter",
                "hook": hook, "prio": -450, "policy": "accept"}, "Wrong early hook priority or policy")
            hooks[hook] = chain
        rules = {}
        for item in objects[4:]:
            rule = {k: v for k, v in item["rule"].items() if k != "handle"}
            hook = rule["chain"]
            require(hook in hooks and hook not in rules and
                    set(rule) == {"family", "table", "chain", "expr"} and
                    rule["family"] == "ip6" and rule["table"] == table_name,
                    "Wrong early rule placement")
            expr = rule["expr"]
            require(len(expr) == 3 and set(expr[0]) == {"match"} and
                    set(expr[1]) == {"counter"} and expr[2] == {"drop": None},
                    "Early gate lacks exact match/counter/drop sequence")
            match = expr[0]["match"]
            require(set(match) == {"op", "left", "right"} and match["op"] == "!=" and
                    match["left"] == {"payload": {"protocol": "ip6", "field": "nexthdr"}} and
                    set(match["right"]) == {"set"}, "Gate does not inspect immediate IPv6 Next Header")
            names = match["right"]["set"]
            require(len(names) == 4 and set(names) == set(protocol_numbers),
                    "Early gate has unsupported allowed headers")
            rules[hook] = [protocol_numbers[name] for name in names]
        require(set(rules) == {"prerouting", "output"}, "Missing early hook")
        require(supplied["hook_priority"] == -450 and supplied["allowed_values"] == [6, 17, 50, 58],
                "Early-gate summary differs from raw configuration")
        result[device] = {"hooks": rules, "priority": -450, "observation_id": raw["id"],
                          "nft_version": objects[0]["metainfo"]["version"],
                          "observed_at": raw["ended_at"],
                          "defragmentation_priority_contract": -400}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    path = Path(args.bundle)
    evidence, commands, phases = load_bundle(path)
    before, after = phases
    early_gates = parse_early_header_gate(path, evidence, commands)
    from nft_source_policy import parse_source_guards
    source_guards = parse_source_guards(path, evidence, commands, phases)
    require(evidence["configuration_id"].startswith("families-"), "Not an address-family case")
    families = [int(value) for value in evidence["configuration_id"].split("-")[-1]]
    require(len(families) == 3 and set(families) <= {4, 6}, "Invalid family tuple")
    device_rows = sorted(evidence["devices"], key=lambda item: item["id"])
    device_index = {device["id"]: index + 1 for index, device in enumerate(device_rows)}
    raw_interfaces = {}
    interfaces = []
    endpoint_zone = {endpoint: link["zone"] for link in evidence["links"] for endpoint in link["endpoints"]}
    for device in device_rows:
        name = device["id"]
        for interface in json.loads(before[name]["interfaces"]["value"]):
            active = "UP" in interface["flags"]
            kind = interface.get("linkinfo", {}).get("info_kind")
            require(not active or interface["ifname"] == "lo" or kind == "veth", "Active unsupported interface kind")
            if not active:
                continue
            identity = name + ":" + interface["ifname"]
            zone = endpoint_zone.get(identity)
            if zone is None:
                require(interface["ifname"] == "lo", "Active interface omitted from declared links")
                zone = "red" if device["role"] in ["host", "inner"] else "gray" if device["role"] == "outer" else "black"
            interfaces.append({"id": identity, "device_id": name, "name": interface["ifname"],
                               "zone": zone, "addresses": interface.get("addr_info", [])})
            raw_interfaces[identity] = interface
    interfaces.sort(key=lambda item: item["id"])
    port_index = {interface["id"]: index for index, interface in enumerate(interfaces)}
    ports = []
    for interface in interfaces:
        device = next(d for d in device_rows if d["id"] == interface["device_id"])
        stack = {"red": [], "gray": [1], "black": [2, 1]}[interface["zone"]]
        origin = device["role"] == "host" and interface["zone"] == "red" and interface["name"] != "lo"
        ports.append("⟨" + str(device_index[device["id"]]) + ", " + quoted(interface["name"]) + ", " +
                     lean_list([str(x) for x in stack]) + ", " + str(origin).lower() + "⟩")
    links = []
    for link in evidence["links"]:
        require(link["relation"] == "veth" and len(link["endpoints"]) == 2, "Unsupported physical link")
        a, b = link["endpoints"]
        left, right = raw_interfaces[a], raw_interfaces[b]
        require(left["link_index"] == right["ifindex"] and right["link_index"] == left["ifindex"],
                "Reciprocal veth interface indices differ")
        namespaces = {d["id"]: d["namespace"] for d in device_rows}
        for source, target, raw_interface in [(a, b, left), (b, a, right)]:
            source_device, target_device = source.split(":")[0], target.split(":")[0]
            peer_records = json.loads(before[source_device]["peer_nsids"]["value"])
            names = json.loads(before[source_device]["named_namespaces"]["value"])
            nsid = raw_interface["link_netnsid"]
            require([r.get("name") for r in peer_records if r["nsid"] == nsid] ==
                    [namespaces[target_device]], "Veth peer namespace ID differs")
            require([r.get("name") for r in names if r.get("id") == nsid] ==
                    [namespaces[target_device]], "Named namespace binding differs")
        links += [[port_index[a], port_index[b]], [port_index[b], port_index[a]]]
    require({p for link in links for p in link} ==
            {port_index[key] for key, value in raw_interfaces.items() if value["ifname"] != "lo"},
            "Active physical link inventory incomplete")
    routes, gateways, records, policies, states, chains = [], [], ["{}"], {}, {}, []
    immediate_gates = {}
    used = []
    for device in device_rows:
        name = device["id"]
        data, later = before[name], after[name]
        for kind in ["policies", "routes4", "routes6"]:
            require(data[kind]["value"] == later[kind]["value"], "State changed across collection: " + name + "/" + kind)
        for family in [4, 6]:
            rule_kind = next((key for key in ["rules" + str(family), "policy-routing" + str(family)]
                              if key in data), None)
            require(rule_kind is not None, "Missing policy-routing observation for " + name + "/" + str(family))
            require(data[rule_kind]["value"] == later[rule_kind]["value"], "Policy-routing rules changed")
            rules = json.loads(data[rule_kind]["value"])
            priorities = {}
            for rule in rules:
                require(set(rule) <= {"priority", "src", "table", "protocol"} and rule.get("src") == "all",
                        "Policy-routing selector requires model extension")
                priorities[str(rule["table"])] = int(rule.get("priority", 0))
            for route in json.loads(data["routes" + str(family)]["value"]):
                route_type = route.get("type", "unicast")
                if route_type in ["local", "broadcast", "anycast"]:
                    continue
                require(route_type in ["unicast", "multicast"], "Unsupported route action")
                require("multipath" not in route and "encap" not in route, "Unsupported route transformation")
                if name + ":" + route.get("dev", "") not in port_index:
                    continue
                low, high, length = address_range(route["dst"], family)
                table = str(route.get("table", "main"))
                require(table in priorities, "Route table has no captured rule")
                for ingress in [i for i in interfaces if i["device_id"] == name]:
                    routes.append([port_index[ingress["id"]], port_index[name + ":" + route["dev"]],
                                   low, high, length, int(route.get("metric", 0)), priorities[table]])
                    gateways.append(encode_address(route["gateway"]) if "gateway" in route else None)
        tag = 1 if device["role"] == "inner" else 2
        policies[name] = policy_blocks(data["policies"]["value"], tag, encode_address)
        states[name] = state_blocks(data["xfrm"]["value"], encode_address)
        require(states[name] == state_blocks(later["xfrm"]["value"], encode_address), "Wire SAs changed")
        immediate_gates[name] = split_filter_and_immediate_gate(data["filters6"]["value"])[1]
        family_hooks = {family: parse_hooks(data["filters" + str(family)]["value"], family) for family in [4, 6]}
        for family in [4, 6]:
            early_text, early_gate = split_filter_and_immediate_gate(data["filters" + str(family)]["value"])
            late_text, late_gate = split_filter_and_immediate_gate(later["filters" + str(family)]["value"])
            require(early_gate == late_gate, "Immediate-header policy changed")
            def filter_structure(text):
                if not text.strip():
                    return ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]",
                            ":OUTPUT ACCEPT [0:0]", "COMMIT"]
                return [re.sub(r"\[\d+:\d+\]", "[0:0]", line) for line in text.splitlines()
                        if line and not line.startswith("#")]
            early_lines, late_lines = filter_structure(early_text), filter_structure(late_text)
            remaining = list(early_lines)
            for line in late_lines:
                if remaining and line == remaining[0]:
                    remaining.pop(0)
                else:
                    tokens = shlex.split(line)
                    require(tokens[:2] == ["-A", "INPUT"] and tokens[-2:] == ["-j", "DROP"],
                            "Filter change is not an additional local-input drop rule")
            require(not remaining, "Existing filter rule or default changed")
        combined = {}
        for hook in ["INPUT", "FORWARD", "OUTPUT"]:
            combined[hook] = sum([family_hooks[family][hook]["parsed_rules"] for family in [4, 6]], [])
            chains.append({"device_id": name, "chain": hook, "family": 0,
                           "policy": "drop", "parsed_rules": combined[hook]})
        local_addresses = sorted({encode_address(address["local"]) for interface in interfaces
                                  if interface["device_id"] == name for address in interface["addresses"]
                                  if address["family"] in ["inet", "inet6"]})
        fields = ["forwardRules := " + render_rules(combined["FORWARD"]),
                  "inputRules := " + render_rules(combined["INPUT"]),
                  "outputRules := " + render_rules(combined["OUTPUT"]),
                  "outbound := " + association_list(policies[name]["out"]),
                  "inbound := " + association_list(policies[name]["in"]),
                  "states := " + lean_list(["⟨" + ", ".join(map(str, state)) + "⟩" for state in states[name]]),
                  "localAddresses := " + lean_list(list(map(str, local_addresses))),
                  "recipientDomain := " + ("some 1" if device["role"] == "host" else "none")]
        records.append("{ " + ", ".join(fields) + " }")
        used += [value["observation_id"] for value in data.values()]
    sources = [port_index[i["id"]] for i in interfaces if i["name"] != "lo" and
               next(d for d in device_rows if d["id"] == i["device_id"])["role"] == "host"]
    black = [port_index[i["id"]] for i in interfaces if i["zone"] == "black"]
    Path(args.output).write_text(render(args.namespace, records, ports, routes, links, [], sources, black,
                                       "snapshot_IPv4_IPv6_ESP_packet_stack"))
    report = {"snapshot": str(path), "model_snapshot": {"devices": device_rows, "interfaces": interfaces, "filters": chains},
              "device_ids": device_index, "port_ids": port_index, "levels": {"L1": 1},
              "early_source_guards": source_guards, "early_header_gates": early_gates, "immediate_header_gates": immediate_gates, "red_family": families[0], "families": families, "routes": routes, "route_gateways": gateways,
              "links": links, "switches": [], "policies": policies, "states": states,
              "observations_used": used, "manifest_sha256": hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest(),
              "scope": "The model uses the before-collection rules exactly. The after capture may insert INPUT DROP rules, which only remove local acceptance. No atomic interval claim is made. Supplemental static namespace IPsec case with family-tagged address keys; logical datagrams with a separately stated fragmentation/reassembly contract. The raw hook gate is post-defragmentation; any validated nft early_header_gates run at priority -450, before the contracted defragmentation priority -400. These exact header gates are retained separately; the packet safety model omits this additional drop-only gate. Positive traces must separately check their received/output header values. No multicast or IPv4-options claim follows."}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"devices": len(device_rows), "ports": len(interfaces), "routes": len(routes), "families": families}))


if __name__ == "__main__":
    main()
