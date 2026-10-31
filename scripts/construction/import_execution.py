"""Import a complete fixed IPv4 packet configuration from raw observations."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from import_snapshot import parse_rule, lean_atom, lean_list, quoted
from raw_correspondence import check_filter_correspondence, raw_observation, parse_iptables_save
from validate_evidence import validate_bundle, require
from analyze_topology import validated_graph
from native_nft_correspondence import check_native_nft


def network_range(value, address_encoder=None):
    network = ipaddress.ip_network("0.0.0.0/0" if value == "default" else value, strict=False)
    require(network.version == 4 or address_encoder is not None, "IPv6 requires the family extension")
    encode = address_encoder or int
    return encode(network.network_address), encode(network.broadcast_address), network.prefixlen


def policy_blocks(text, tag, address_encoder=None):
    result = {"in": [], "out": [], "fwd": [], "socket": []}
    for block in re.split(r"(?m)(?=^src )", text):
        if not block.strip():
            continue
        if re.search(r"(?m)^\s*socket (in|out) priority 0\s*$", block):
            require(re.fullmatch(r"src \S+ dst \S+\s+socket (?:in|out) priority 0\s*", block), "Unsupported socket policy")
            result["socket"].append(block)
            continue
        matched = re.fullmatch(r"src (\S+) dst (\S+)\s+dir (in|out|fwd) priority (\d+)\s+tmpl src (\S+) dst (\S+)\s+proto esp (?:spi (0x[0-9a-f]+) )?reqid (\d+) mode tunnel\s*", block)
        require(matched is not None, "Unsupported SPD entry: " + block)
        source, destination, direction, priority, sender, receiver, spi, request = matched.groups()
        sl, sh, _ = network_range(source, address_encoder)
        dl, dh, _ = network_range(destination, address_encoder)
        encode = address_encoder or (lambda value: int(ipaddress.IPv4Address(value)))
        result[direction].append([int(request), tag, encode(ipaddress.ip_address(sender)), encode(ipaddress.ip_address(receiver)), sl, sh, dl, dh, int(priority), int(spi, 16) if spi else None])
    require(sorted(result["in"]) == sorted(result["fwd"]), "Inbound and forward selectors differ")
    return result


def state_blocks(text, address_encoder=None):
    result = []
    for block in re.split(r"(?m)(?=^src )", text):
        if not block.strip():
            continue
        matched = re.match(r"src (\S+) dst (\S+)\s+proto esp spi (0x[0-9a-f]+)(?:\(\d+\))? reqid (\d+)(?:\(0x[0-9a-f]+\))? mode tunnel\b", block)
        require(matched is not None, "Unsupported SAD entry")
        require(not re.search(r"\b(?:encap|mark|if_id|offload)\b", block), "SAD feature requires an extension")
        sender, receiver, spi, request = matched.groups()
        encode = address_encoder or (lambda value: int(ipaddress.IPv4Address(value)))
        result.append([int(request), int(spi, 16), encode(ipaddress.ip_address(sender)), encode(ipaddress.ip_address(receiver))])
    return result


def rendered_rule(rule):
    parsed = parse_rule(rule)
    return "⟨" + lean_list([lean_atom(atom) for atom in parsed["atoms"]]) + ", ." + parsed["verdict"] + "⟩"


def tuple_list(rows):
    return lean_list(["⟨" + ", ".join(str(x) for x in row) + "⟩" for row in rows])


def association_list(rows):
    return lean_list(["⟨" + ", ".join(str(x) for x in row[:-1]) + ", " + ("none" if row[-1] is None else "some " + str(row[-1])) + "⟩" for row in rows])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    parser.add_argument("--supplement", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--include-recorded-sa-epochs", action="store_true")
    args = parser.parse_args()
    bundle = Path(args.snapshot)
    validation = validate_bundle(bundle)
    snapshot = json.loads((bundle / "snapshot.json").read_text())
    topology = validated_graph(bundle)
    require(all(link["relation"] in {"veth", "ovs_bridge_membership"} for link in snapshot["links"]), "Additional link kind requires execution semantics")
    require(not any(i["link_kind"] == "bridge" for i in snapshot["interfaces"]), "Linux bridge requires execution semantics")
    spec = json.loads((bundle / "spec.json").read_text())
    declared_devices = {d["id"]: d for d in spec["devices"]}
    require(set(declared_devices) == {d["id"] for d in snapshot["devices"]}, "Declared device inventory mismatch")
    for device in snapshot["devices"]:
        declared = declared_devices[device["id"]]
        require(device["role"] == declared["role"], "Declared role mismatch")
        require(device["security_level_id"] == declared.get("level"), "Declared security-level mismatch")
    for interface in snapshot["interfaces"]:
        declared = next((i for i in declared_devices[interface["device_id"]]["interfaces"] if i["name"] == interface["name"]), None)
        if declared is None:
            require(interface["zone"] == "local", "Undeclared nonlocal port")
        else:
            require(interface["zone"] == declared["zone"], "Port zone differs from declared architecture")
    filter_check = check_filter_correspondence(bundle, snapshot)
    nft_check = check_native_nft(bundle, snapshot)
    supplement_path = Path(args.supplement)
    supplement_manifest = json.loads((supplement_path / "manifest.json").read_text())
    for item in supplement_manifest["files"]:
        require(hashlib.sha256((supplement_path / item["path"]).read_bytes()).hexdigest() == item["sha256"], "Supplement hash mismatch")
    supplement = json.loads((supplement_path / "observations.json").read_text())
    devices = sorted(snapshot["devices"], key=lambda d: d["id"])
    device_index = {d["id"]: n + 1 for n, d in enumerate(devices)}
    require(set(supplement["expected_device_ids"]) == set(device_index), "Supplement device coverage mismatch")
    interfaces = sorted(snapshot["interfaces"], key=lambda i: i["id"])
    port_index = {i["id"]: n for n, i in enumerate(interfaces)}
    require(len(port_index) == len(interfaces), "Duplicate interface")
    levels = {level: n + 1 for n, level in enumerate(sorted({d["security_level_id"] for d in devices if d["security_level_id"]}))}
    observations_used = []
    raw_interfaces = {}
    raw_routes = {}
    device_records = ["{}"]
    port_records = []
    routes = []
    route_gateways = []
    policy_summary = {}
    states_by_device = {}
    socket_policy_count = 0
    epoch_records = []

    def observation(device, kind):
        candidates = [o for o in snapshot["observations"] if o["device_id"] == device and o["kind"] == kind]
        require(len(candidates) == 1, "Observation coverage: " + device + "/" + kind)
        obs, stdout = raw_observation(bundle, snapshot, candidates[0]["id"])
        observations_used.append(obs["id"])
        return stdout

    def supplemental(device, kind):
        records = [r for r in supplement["records"] if r["device_id"] == device and r["kind"] == kind]
        require(len(records) == 2 and {r["phase"] for r in records} == {"before", "after"}, "Supplement coverage")
        require(all(r["returncode"] == 0 for r in records), "Supplement command failed")
        records.sort(key=lambda r: r["phase"] != "before")
        return records

    for device in devices:
        identifier = device["id"]
        raw_ifaces = json.loads(observation(identifier, "interfaces"))
        device_ifaces = [i for i in interfaces if i["device_id"] == identifier]
        require({i["name"] for i in device_ifaces} == {i["ifname"] for i in raw_ifaces}, "Interface inventory mismatch")
        for interface in device_ifaces:
            raw = next(r for r in raw_ifaces if r["ifname"] == interface["name"])
            require(interface["addresses"] == raw.get("addr_info", []), "Interface address normalization mismatch")
            require(interface["observed_up"] == ("UP" in raw["flags"]), "Interface administrative-state mismatch")
            raw_interfaces[interface["id"]] = raw
        raw_route_list = json.loads(observation(identifier, "routes4"))
        raw_routes[identifier] = raw_route_list
        normalized_routes = [r for r in snapshot["routes"] if r["device_id"] == identifier and r["family"] == 4]
        require([r["raw"] for r in normalized_routes] == raw_route_list, "Route inventory mismatch")
        routing_records = supplemental(identifier, "policy-routing4")
        rules = json.loads(routing_records[0]["stdout"])
        require(rules == json.loads(routing_records[1]["stdout"]), "Policy routing changed during supplement")
        table_priority = {}
        for rule in rules:
            require(set(rule) == {"priority", "src", "table"} and rule["src"] == "all", "Nontrivial policy routing requires extension")
            table = str(rule["table"])
            table_priority[table] = min(table_priority.get(table, rule["priority"]), rule["priority"])
        for route in raw_route_list:
            require(set(route) <= {"dst", "dev", "gateway", "protocol", "scope", "prefsrc", "flags", "metric", "table", "type", "nhid"}, "Unsupported route fields")
            require(route.get("type", "unicast") in {"unicast", "local", "broadcast"}, "Terminating or multipath route requires extension")
            table = str(route.get("table", "main"))
            require(table in table_priority, "Route table has no supported policy lookup")
            output = identifier + ":" + route["dev"]
            require(output in port_index, "Route references absent port")
            low, high, prefix = network_range(route.get("dst", "default"))
            for entry in device_ifaces:
                routes.append([port_index[entry["id"]], port_index[output], low, high, prefix, route.get("metric", 0), table_priority[table]])
                route_gateways.append(int(ipaddress.IPv4Address(route["gateway"])) if "gateway" in route else None)
        for record in supplemental(identifier, "routes4"):
            require(json.loads(record["stdout"]) == raw_route_list, "Routes differ from packet snapshot")
        for o in snapshot["observations"]:
            if o["device_id"] == identifier and o["kind"] == "convergence-routes4":
                _, text = raw_observation(bundle, snapshot, o["id"])
                require(json.loads(text) == raw_route_list, "Convergence route inventory differs")
                observations_used.append(o["id"])
        chains = [c for c in snapshot["filters"] if c["device_id"] == identifier and c["family"] == 4 and c["table"] == "filter"]
        require({c["chain"] for c in chains} == {"INPUT", "FORWARD", "OUTPUT"} and len(chains) == 3, "Unsupported chains")
        for record in supplemental(identifier, "all-tables4"):
            table_names = re.findall(r"(?m)^\*(\S+)$", record["stdout"])
            require(table_names == ["filter"], "Additional netfilter table requires semantic review")
            parsed = parse_iptables_save(record["stdout"])
            for chain in chains:
                require(parsed[chain["chain"]]["policy"] == chain["policy"], "Supplement default differs")
                require([(r["tokens"], r["action"]) for r in parsed[chain["chain"]]["rules"]] == [(r["matches"]["iptables_tokens"], r["action"]) for r in chain["ordered_rules"]], "Supplement filter differs")
        for o in snapshot["observations"]:
            if o["device_id"] == identifier and o["kind"] == "convergence-filters4":
                _, text = raw_observation(bundle, snapshot, o["id"])
                parsed = parse_iptables_save(text)
                for chain in chains:
                    require(parsed[chain["chain"]]["policy"] == chain["policy"], "Convergence filter default differs")
                    require([(r["tokens"], r["action"]) for r in parsed[chain["chain"]]["rules"]] == [(r["matches"]["iptables_tokens"], r["action"]) for r in chain["ordered_rules"]], "Convergence filter rules differ")
                observations_used.append(o["id"])
        tag = {"inner": 1, "outer": 2}.get(device["role"], 0)
        policy_text = observation(identifier, "policies")
        policy = policy_blocks(policy_text, tag)
        require(tag != 0 or not any(policy[x] for x in ["in", "out", "fwd"]), "Unclassified encryption device")
        socket_policy_count += len(policy["socket"])
        states = state_blocks(observation(identifier, "states"))
        require(tag != 0 or not states, "Unclassified installed SA")
        if args.include_recorded_sa_epochs:
            policy_epochs = []
            state_epochs = []
            for o in snapshot["observations"]:
                if o["device_id"] != identifier:
                    continue
                if o["kind"] in {"policies", "convergence-policies", "states", "convergence-states"}:
                    _, text = raw_observation(bundle, snapshot, o["id"])
                    metadata = {"source": "snapshot", "id": o["id"], "started_at": o["started_at"], "ended_at": o["ended_at"], "raw_sha256": o["raw_sha256"]}
                    if "policies" in o["kind"]:
                        policy_epochs.append((metadata, policy_blocks(text, tag)))
                    else:
                        state_epochs.append((metadata, state_blocks(text)))
                    observations_used.append(o["id"])
            for kind in ["xfrm-policy-main", "xfrm-states-detailed-nokeys"]:
                for record in supplemental(identifier, kind):
                    metadata = {"source": "processing-supplement", "id": record["id"], "phase": record["phase"], "started_at": record["started_at"], "ended_at": record["ended_at"], "stdout_sha256": hashlib.sha256(record["stdout"].encode()).hexdigest()}
                    if kind == "xfrm-policy-main":
                        policy_epochs.append((metadata, policy_blocks(record["stdout"], tag)))
                    else:
                        state_epochs.append((metadata, state_blocks(record["stdout"])))
            for metadata, candidate in policy_epochs:
                for direction in ["in", "out", "fwd"]:
                    require({tuple(p[:9]) for p in candidate[direction]} == {tuple(p[:9]) for p in policy[direction]}, "SPD selectors/endpoints/priorities changed across retained epochs")
                epoch_records.append({"device": identifier, "kind": "SPD", **metadata, "policies": candidate})
            for metadata, candidate in state_epochs:
                require({(sa[0], sa[2], sa[3]) for sa in candidate} == {(sa[0], sa[2], sa[3]) for sa in states}, "SAD local binding/endpoints changed across retained epochs")
                epoch_records.append({"device": identifier, "kind": "SAD", **metadata, "states": candidate})
            for direction in ["in", "out", "fwd"]:
                policy[direction] = [list(p) for p in sorted({tuple(p) for _, candidate in policy_epochs for p in candidate[direction]}, key=str)]
            states = [list(sa) for sa in sorted({tuple(sa) for _, candidate in state_epochs for sa in candidate})]
        states_by_device[identifier] = states
        policy_summary[identifier] = policy
        require(all(not r["stdout"].strip() for r in supplemental(identifier, "xfrm-policy-sub")), "Sub-policy must be modeled")
        fields = []
        for hook in ["forward", "input", "output"]:
            chain = next(c for c in chains if c["chain"] == hook.upper())
            fields.append(hook + "Rules := " + lean_list([rendered_rule(r) for r in chain["ordered_rules"]]))
            fields.append(hook + "Fallback := ." + {"drop": "deny", "accept": "allow"}[chain["policy"]])
        fields += ["outbound := " + association_list(policy["out"]), "inbound := " + association_list(policy["in"]), "states := " + tuple_list(states)]
        addresses = sorted({int(ipaddress.IPv4Address(a["local"])) for i in device_ifaces for a in i["addresses"] if a["family"] == "inet"})
        fields.append("localAddresses := " + lean_list([str(a) for a in addresses]))
        fields.append("recipientDomain := " + ("some " + str(levels[device["security_level_id"]]) if device["role"] == "host" else "none"))
        device_records.append("{ " + ", ".join(fields) + " }")
    for interface in interfaces:
        device = next(d for d in devices if d["id"] == interface["device_id"])
        zone = interface["zone"]
        if zone == "local":
            zone = {"transport": "black", "firewall": "black", "gray-firewall": "gray", "switch": "gray", "outer": "gray"}.get(device["role"], "red")
        require(zone in {"red", "gray", "black"}, "Unsupported port zone")
        stack = {"red": [], "gray": [1], "black": [2, 1]}[zone]
        origin = device["role"] == "host" and interface["zone"] == "red"
        port_records.append("⟨" + str(device_index[interface["device_id"]]) + ", " + quoted(interface["name"]) + ", " + lean_list([str(x) for x in stack]) + ", " + str(origin).lower() + "⟩")
    links = []
    switching = []
    for link in snapshot["links"]:
        if link["relation"] != "veth":
            continue
        a, b = link["endpoint_interface_ids"]
        left, right = raw_interfaces[a], raw_interfaces[b]
        require(left.get("link_index") == right["ifindex"] and right.get("link_index") == left["ifindex"], "Raw veth reciprocity failed")
        links.extend([[port_index[a], port_index[b]], [port_index[b], port_index[a]]])
    physical = {i["id"] for i in interfaces if i["link_kind"] == "veth"}
    require({i for l in snapshot["links"] if l["relation"] == "veth" for i in l["endpoint_interface_ids"]} == physical, "Physical link inventory incomplete")
    for device in devices:
        if device["role"] != "switch":
            continue
        values = [r for r in snapshot["native_runtime"] if r["device_id"] == device["id"]]
        flows = [r for r in values if r["kind"] == "native-ovs-flows"]
        require(len(flows) == 1, "Missing OVS flow inventory")
        require(flows[0]["raw_value"].strip() == "reset_counts priority=0 actions=NORMAL", "Non-NORMAL OVS processing requires extension")
        ports = [i for i in interfaces if i["device_id"] == device["id"] and i["link_kind"] == "veth"]
        require(ports, "Empty physical bridge membership")
        switching.extend([[port_index[a["id"]], port_index[b["id"]]] for a in ports for b in ports if a != b])
    lines = ["import TDN.Targets.PacketExecution", "import TDN.Semantics.ExecutionProvenance", "", "namespace TDN.Imported." + args.namespace, "", "open Execution", "", "set_option maxRecDepth 1000000", "set_option maxHeartbeats 0", "", "def devices : List DeviceData := " + lean_list(device_records), "", "def ports : List PortData := " + lean_list(port_records), "", "def routes : List Route := " + tuple_list(routes), "", "def links : List (Nat × Nat) := " + tuple_list(links), "", "def switches : List (Nat × Nat) := " + tuple_list(switching), "", "def config : Config := finiteConfig devices ports routes links switches", "def layout : Nat → List Nat := finiteLayout ports", "", "lemma forward_checks : FiniteForwardChecks devices ports := by", "  unfold FiniteForwardChecks devices ports", "  decide", "", "end TDN.Imported." + args.namespace, ""]
    checks = [
        "lemma peer_tag_checks : FinitePeerTagAgreement devices := by",
        "  unfold FinitePeerTagAgreement devices StateBindsPolicy SameWireAssociation; decide",
        "lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=",
        "  finite_peer_tag_agreement_sound devices ports routes links switches peer_tag_checks",
        "",
        "lemma route_owner_checks : ∀ r ∈ routes, (portAt ports r.egress).owner = (portAt ports r.ingress).owner := by",
        "  unfold routes ports; decide",
        "lemma link_checks : ∀ edge ∈ links, (portAt ports edge.1).stack = (portAt ports edge.2).stack := by",
        "  unfold links ports; decide",
        "lemma switch_checks : ∀ edge ∈ switches, (portAt ports edge.1).stack = (portAt ports edge.2).stack ∧ (deviceAt devices (portAt ports edge.1).owner).inbound = [] := by",
        "  unfold switches ports devices; decide",
        "lemma forward_default_checks : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny := by",
        "  unfold devices; decide",
        "lemma output_checks : FiniteOutputChecks devices ports := by",
        "  unfold FiniteOutputChecks devices ports; decide",
        "lemma outer_route_checks : FiniteOuterRoutes devices ports routes := by",
        "  unfold FiniteOuterRoutes devices ports routes; decide",
        "",
        "lemma local_stack_conditions : LocalStackConditions config layout :=",
        "  local_stack_conditions_of_finite_checks devices ports routes links switches",
        "    route_owner_checks link_checks switch_checks forward_default_checks forward_checks output_checks outer_route_checks",
        "",
        "theorem every_transmission_has_port_stack {start finish : Execution.State} {actions : List Action}",
        "    (run : (lts config).MTr start actions finish) (initial : StackInvariant config layout start)",
        "    (ready : finish.phase = .ready) : finish.frame.tags = layout finish.port :=",
        "  transmitted_stack config layout local_stack_conditions run initial ready",
        ""
    ]
    sources = [str(port_index[i["id"]]) for i in interfaces if i["zone"] == "red" and next(d for d in devices if d["id"] == i["device_id"])["role"] == "host"]
    black_ports = [str(port_index[i["id"]]) for i in interfaces if i["zone"] == "black"]
    checks += [
        "def redSources : List Nat := " + lean_list(sources),
        "def blackPorts : List Nat := " + lean_list(black_ports),
        "lemma sources_checked : ∀ p ∈ redSources, layout p = [] ∧ config.payloadOrigin p := by",
        "  unfold redSources layout config finiteLayout finiteConfig ports; decide",
        "lemma black_ports_checked : ∀ p ∈ blackPorts, layout p = [2, 1] := by",
        "  unfold blackPorts layout finiteLayout ports; decide",
        "theorem snapshot_RG007_IPv4_ESP_packet_stack : Targets.msc_protected_red_payload_stack config redSources blackPorts :=",
        "  Targets.protected_red_stack_from_local_checks config layout redSources blackPorts",
        "    local_stack_conditions sources_checked black_ports_checked",
        ""
    ]
    lines[-3:-3] = checks
    Path(args.output).write_text("\n".join(lines))
    report = {"snapshot": str(bundle), "supplement": str(supplement_path), "validation": validation, "filter_correspondence": filter_check, "native_nft_correspondence": nft_check, "native_and_namespace_correspondence": topology["native_runtime"], "checked_inactive_interfaces": topology["inactive_interfaces"], "device_count": len(devices), "port_count": len(interfaces), "route_count": len(routes), "routes": routes, "route_gateways": route_gateways, "links": links, "switches": switching, "directed_links": len(links), "directed_switches": len(switching), "socket_policies": socket_policy_count, "device_ids": device_index, "port_ids": port_index, "levels": levels, "states": states_by_device, "policies": policy_summary, "observations_used": sorted(set(observations_used)), "epoch_records": epoch_records, "epoch_scope": "Conservative union of explicitly retained SPD/SAD observations; positive execution is model satisfiability, not an observed simultaneous mixed-epoch run" if args.include_recorded_sa_epochs else "Single selected raw SPD/SAD observation per device; collection consistency retained separately", "scope": "Fixed IPv4 tunnel ESP configurations; Red-host payload origins. OVS NORMAL switching overapproximated by all physical bridge member destinations. Additional drop-only checks and local-route distinctions are overapproximated, not exact acceptance.", "remaining": ["This importer supplies the native IPv4 configuration; separate generated local stack, full-label, byte-response and positive-path modules must be validated together", "Socket-bound IKE bypass remains scoped to the captured trusted IKE programs", "Authenticated encrypted assembly uses the declared cryptographic and kernel-processing correspondence; ordinary fragment keys do not establish shared provenance", "Separate IPv6, MACsec, carrier and FreeBSD applications retain their own backend scope and completion records"]}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ["device_count", "port_count", "route_count", "directed_links", "directed_switches", "socket_policies"]}))


if __name__ == "__main__":
    main()
