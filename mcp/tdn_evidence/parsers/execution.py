"""Validate retained IPv4 execution observations and return typed JSON records."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from .packet_policy import parse_rule
from .correspondence import check_filter_correspondence, raw_observation, parse_iptables_save
from .snapshot import validate_bundle, require, safe_path
from .topology import validated_graph
from .native_nft import check_native_nft


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


def empty_device():
    return {"forwardRules": [], "inputRules": [], "outputRules": [],
            "forwardFallback": "deny", "inputFallback": "deny", "outputFallback": "deny",
            "egressPolicies": [], "ingressPolicies": [], "states": [], "localAddresses": [],
            "ifaceSecurityDomain": None}


def rule_json(rule):
    from ..projections import atom_json
    parsed = parse_rule(rule)
    return {"atoms": [atom_json(atom) for atom in parsed["atoms"]], "verdict": parsed["verdict"]}


def association_json(row):
    fields = ["id", "tag", "sender", "receiver", "sourceLow", "sourceHigh",
              "destinationLow", "destinationHigh", "priority", "requiredSpi"]
    require(len(row) == len(fields), "Unexpected association record")
    return dict(zip(fields, row))


def state_json(row):
    require(len(row) == 4, "Unexpected security association record")
    return dict(zip(["reqid", "spi", "sender", "receiver"], row))


def binding_records(snapshot, device_ids, port_ids, devices, policies, states):
    declared = {device["id"]: device for device in snapshot["devices"]}
    ports = []
    sources = []
    for interface in snapshot["interfaces"]:
        owner = declared[interface["device_id"]]
        data_port = interface["zone"] in {"red", "gray", "black"}
        record = {"portId": port_ids[interface["id"]], "interfaceId": interface["id"],
            "ownerId": device_ids[owner["id"]], "ownerDeviceId": owner["id"],
            "declaredZone": interface["zone"], "declaredRole": owner["role"],
            "linkKind": interface["link_kind"], "observedUp": interface["observed_up"],
            "mtu": interface["mtu"],
            "emulatedAttachment": interface["link_kind"] == "veth",
            "physicalIndependence": owner.get("physical_independence", "unavailable"),
            "managementNetwork": not data_port and interface["zone"] != "local",
            "externalDataPort": (owner["role"] == "inner" and interface["zone"] == "gray") or
                (owner["role"] == "outer" and interface["zone"] == "black"),
            "observationIds": interface["observation_ids"]}
        ports.append(record)
        if owner["role"] == "host" and interface["zone"] == "red":
            sources.append({"portId": record["portId"], "interfaceId": interface["id"],
                "deviceId": owner["id"], "networkId": owner.get("network_id"),
                "site": owner.get("site"), "securityLevelId": owner.get("security_level_id"),
                "originDomain": devices[device_ids[owner["id"]]]["ifaceSecurityDomain"],
                "kind": "declared-red-data-attachment", "observationIds": interface["observation_ids"]})
    tunnels = []
    for tunnel in snapshot["tunnels"]:
        sender, receiver = tunnel["device_id"], tunnel["peer_device_id"]
        require(sender in declared and receiver in declared, "Tunnel endpoint device is absent")
        local = int(ipaddress.IPv4Address(tunnel["endpoints"]["local"]))
        remote = int(ipaddress.IPv4Address(tunnel["endpoints"]["remote"]))
        tag = {"inner": 1, "outer": 2}[tunnel["layer"]]
        candidates = {tuple(state[1:]) for component in [sender, receiver]
                      for state in states[component] if state[2:] == [local, remote]}
        for spi, source, destination in sorted(candidates):
            local_rows = [state for state in states[sender] if state[1:] == [spi, source, destination]]
            peer_rows = [state for state in states[receiver] if state[1:] == [spi, source, destination]]
            outbound = [association_json(row) for row in policies[sender]["out"]
                        if any(state[0] == row[0] for state in local_rows) and
                        row[2:4] == [source, destination] and row[9] in [None, spi]]
            inbound = [association_json(row) for row in policies[receiver]["in"]
                       if row[2:4] == [source, destination] and row[9] in [None, spi] and
                       any(state[0] == row[0] for state in peer_rows)]
            tunnels.append({"tunnelId": tunnel["id"], "senderDeviceId": sender,
                "receiverDeviceId": receiver,
                "seal": {"tag": tag, "association": spi, "sender": source, "receiver": destination},
                "senderInstalled": bool(local_rows), "receiverInstalled": bool(peer_rows),
                "senderPolicies": outbound, "receiverPolicies": inbound,
                "sourceObservationIds": tunnel["observation_ids"]})
    seals = [(row["seal"]["tag"], row["seal"]["association"], row["seal"]["sender"],
              row["seal"]["receiver"]) for row in tunnels]
    require(len(seals) == len(set(seals)), "A wire association has ambiguous declared tunnel bindings")
    return {"ifaceBindings": ports, "sourceAttachments": sources, "ipsecTunnelBindings": tunnels,
            "bindingLimitations": ["Missing declared network IDs require an explicit network-to-attachment map",
                "Role and zone labels are architectural assignments checked against observations",
                "Shared-kernel attachments do not establish physical hardware independence"]}


def parse_execution(directory, supplement, include_recorded_sa_epochs=False):
    bundle = Path(directory)
    validation = validate_bundle(bundle)
    snapshot = json.loads((bundle / "snapshot.json").read_text())
    require(all(t["mechanism"] == "IPsec" for t in snapshot["tunnels"]),
            "This execution parser supports the native IPv4 IPsec profile; use a matching parser for other mechanisms")
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
    supplement_path = Path(supplement)
    supplement_manifest = json.loads((supplement_path / "manifest.json").read_text())
    for item in supplement_manifest["files"]:
        require(hashlib.sha256(safe_path(supplement_path, item["path"]).read_bytes()).hexdigest() == item["sha256"], "Supplement hash mismatch")
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
    device_records = [empty_device()]
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
            require(type(raw.get("mtu")) is int and raw["mtu"] > 0 and
                    interface.get("mtu") == raw["mtu"], "Interface MTU normalization mismatch")
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
        if include_recorded_sa_epochs:
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
        fields = empty_device()
        for hook in ["forward", "input", "output"]:
            chain = next(c for c in chains if c["chain"] == hook.upper())
            fields[hook + "Rules"] = [rule_json(rule) for rule in chain["ordered_rules"]]
            fields[hook + "Fallback"] = {"drop": "deny", "accept": "allow"}[chain["policy"]]
        fields["egressPolicies"] = [association_json(row) for row in policy["out"]]
        fields["ingressPolicies"] = [association_json(row) for row in policy["in"]]
        fields["states"] = [state_json(row) for row in states]
        fields["localAddresses"] = sorted({int(ipaddress.IPv4Address(a["local"]))
            for interface in device_ifaces for a in interface["addresses"] if a["family"] == "inet"})
        fields["ifaceSecurityDomain"] = levels[device["security_level_id"]] if device["role"] == "host" else None
        device_records.append(fields)
    for interface in interfaces:
        device = next(d for d in devices if d["id"] == interface["device_id"])
        zone = interface["zone"]
        if zone == "local":
            zone = {"transport": "black", "firewall": "black", "gray-firewall": "gray", "switch": "gray", "outer": "gray"}.get(device["role"], "red")
        require(zone in {"red", "gray", "black"}, "Unsupported port zone")
        stack = {"red": [], "gray": [1], "black": [2, 1]}[zone]
        origin = device["role"] == "host" and interface["zone"] == "red"
        port_records.append({"owner": device_index[interface["device_id"]],
            "name": interface["name"], "stack": stack, "canOriginateTraffic": origin})
    links = []
    bridging = []
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
        bridging.extend([[port_index[a["id"]], port_index[b["id"]]] for a in ports for b in ports if a != b])
    sources = [port_index[i["id"]] for i in interfaces if i["zone"] == "red" and
               next(d for d in devices if d["id"] == i["device_id"])["role"] == "host"]
    black = [port_index[i["id"]] for i in interfaces if i["zone"] == "black"]
    gray = [port_index[i["id"]] for i in interfaces if i["zone"] == "gray"]
    route_fields = ["ingress", "egress", "destPrefixLow", "destPrefixHigh", "prefixLength", "metric", "tablePriority"]
    bindings = binding_records(snapshot, device_index, port_index, device_records,
                              policy_summary, states_by_device)
    return {
        **bindings,
        "devices": device_records, "ports": port_records,
        "routes": [dict(zip(route_fields, row)) for row in routes],
        "links": links, "bridges": bridging, "macIfaces": [], "carriers": [],
        "redSources": sources, "grayIfaces": gray, "blackIfaces": black,
        "deviceIds": device_index, "portIds": port_index, "levels": levels,
        "routeGateways": route_gateways,
        "sourceDevices": snapshot["devices"], "sourceInterfaces": snapshot["interfaces"],
        "sourceTunnels": snapshot["tunnels"],
        "sourceBindings": [{"id": o["id"], "device": o["device_id"],
            "kind": o["kind"], "rawPath": o["raw_path"], "rawSha256": o["raw_sha256"],
            "started": o["started_at"], "finished": o["ended_at"]}
            for o in snapshot["observations"] if o["id"] in observations_used],
        "supplementManifestSha256": hashlib.sha256((supplement_path / "manifest.json").read_bytes()).hexdigest(),
        "validation": {"snapshot": validation, "filterCorrespondence": filter_check,
            "nativeNftCorrespondence": nft_check,
            "nativeRuntime": topology["native_runtime"],
            "inactiveInterfaces": topology["inactive_interfaces"]},
        "socketPolicyCount": socket_policy_count, "epochRecords": epoch_records,
        "scope": {"family": "IPv4", "mechanisms": ["IPsec tunnel ESP"],
            "switching": "All OVS NORMAL physical member destinations",
            "epochs": "union of retained observations" if include_recorded_sa_epochs else "single selected observations",
            "claimsSimultaneousEpochs": False,
            "limitations": ["Socket-bound IKE policies rely on the captured trusted IKE programs",
                "The finite data requires separate checked execution and provenance lemmas",
                "IPv6, MACsec and carrier evidence require their corresponding parser"]}}
