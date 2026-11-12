"""Construct an explicit microstep trace and emit Lean checks for every transition."""
import argparse
import copy
from collections import deque
import ipaddress
import json
from pathlib import Path
from network_names import forwarding_lean
from import_snapshot import parse_rule, quoted, lean_list
from import_execution import association_list, tuple_list
from validate_evidence import require


def packet_lean(packet):
    fields = []
    for key, value in packet.items():
        if isinstance(value, str):
            encoded = quoted(value)
        elif isinstance(value, list):
            encoded = lean_list([str(x) for x in value])
        else:
            encoded = str(value)
        fields.append(key + " := " + encoded)
    return "{ " + ", ".join(fields) + " }"


def frame_lean(frame):
    encapLayers = ["⟨⟨" + ", ".join(str(x) for x in envelope["seal"]) + "⟩, " + packet_lean(envelope["header"]) + "⟩" for envelope in frame["encapLayers"]]
    return "{ payload := 1, originDomain := " + str(frame["originDomain"]) + ", enteredIface := " + str(frame["enteredIface"]) + ", packet := " + packet_lean(frame["packet"]) + ", encapLayers := " + lean_list(encapLayers) + " }"


def matches(association, packet):
    return association[4] <= packet["source"] <= association[5] and association[6] <= packet["destination"] <= association[7]


def selected(policies, packet):
    candidates = [a for a in policies if matches(a, packet)]
    return [a for a in candidates if a[8] == min(x[8] for x in candidates)] if candidates else []


def bound(association, sa):
    return sa[0] == association[0] and sa[2] == association[2] and sa[3] == association[3] and (association[9] is None or association[9] == sa[1])


def atom_holds(atom, packet):
    kind = atom["kind"]
    if kind in {"sourceRange", "destinationRange"}:
        return atom["low"] <= packet["source" if kind == "sourceRange" else "destination"] <= atom["high"]
    if kind in {"sourcePorts", "destinationPorts", "connectionStates"}:
        return packet[{"sourcePorts": "sourcePort", "destinationPorts": "destinationPort", "connectionStates": "connectionState"}[kind]] in atom["values"]
    if kind in {"inboundPolicy", "outboundPolicy"}:
        return atom["value"] in packet["matchedInboundPolicyIds" if kind == "inboundPolicy" else "matchedOutboundPolicyIds"]
    return packet.get(kind, 0) == atom["value"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--module", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--source-port", required=True)
    parser.add_argument("--destination-port", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--trace", required=True)
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text())
    snapshot = report.get("model_snapshot") or json.loads((Path(report["snapshot"]) / "snapshot.json").read_text())
    interfaces = {i["id"]: i for i in snapshot["interfaces"]}
    ports = {number: interfaces[name] for name, number in report["port_ids"].items()}
    devices = {d["id"]: d for d in snapshot["devices"]}
    chains = {(c["device_id"], c["chain"]): c for c in snapshot["filters"] if c["family"] in [0, 4]}
    source = interfaces[args.source_port]
    destination = interfaces[args.destination_port]
    red_family = report.get("red_family", 4)
    def encode(value):
        parsed = ipaddress.ip_address(value)
        return int(parsed) + (2 ** 128 if parsed.version == 6 else 0)
    def level(device):
        return report["levels"].get(device.get("security_level_id", "L1"), 1)
    address = lambda interface: encode(next(a["local"] for a in interface["addresses"]
        if a["family"] == ("inet" if red_family == 4 else "inet6") and a.get("scope") != "link"))
    port = report["port_ids"][args.source_port]
    frame = {"payload": 1, "originDomain": level(devices[source["device_id"]]), "enteredIface": port, "packet": {"source": address(source), "destination": address(destination), "protocol": "icmp" if red_family == 4 else "ipv6-icmp", "ingress": source["name"], "egress": "", "sourcePort": 0, "destinationPort": 0, "ipv4HeaderWords": 5 if red_family == 4 else 0, "ipv6NextHeader": 0 if red_family == 4 else 58, "matchedInboundPolicyIds": [], "matchedOutboundPolicyIds": [], "connectionState": "NEW", "icmpType": 8 if red_family == 4 else 128, "icmpCode": 0, "hopLimit": 64}, "encapLayers": []}
    state = {"port": port, "phase": "localOutput", "frame": frame, "authenticated": []}
    states = [copy.deepcopy(state)]
    steps = []
    next_hop = None

    def distance_to_address(start, target):
        targets = {number for number, interface in ports.items() if any(a["family"] in ["inet", "inet6"] and encode(a["local"]) == target for a in interface["addresses"])}
        pending = deque([(start, 0)])
        seen = set()
        while pending:
            number, distance = pending.popleft()
            if number in targets:
                return distance
            if number in seen:
                continue
            seen.add(number)
            neighbors = [b for a, b in report["links"] + report["switches"] if a == number]
            neighbors += [other for other, interface in ports.items() if interface["device_id"] == ports[number]["device_id"]]
            pending.extend((neighbor, distance + 1) for neighbor in neighbors if neighbor not in seen)
        return 1000000

    def add(action, constructor, arguments):
        steps.append({"action": action, "constructor": constructor, "arguments": arguments})
        states.append(copy.deepcopy(state))

    def policy_packet():
        packet = copy.deepcopy(state["frame"]["packet"])
        current = ports[state["port"]]
        packet["egress"] = current["name"]
        packet["matchedInboundPolicyIds"] = state["authenticated"]
        packet["matchedOutboundPolicyIds"] = [a[0] for a in selected(report["policies"][current["device_id"]]["out"], packet)]
        return packet

    def accepts(hook):
        chain = chains[(ports[state["port"]]["device_id"], hook)]
        packet = policy_packet()
        for rule in chain.get("parsed_rules", chain.get("ordered_rules", [])):
            parsed = rule if "atoms" in rule else parse_rule(rule)
            if all(atom_holds(a, packet) for a in parsed["atoms"]):
                return parsed["verdict"] == "allow"
        return chain["policy"] == "accept"

    for _ in range(300):
        current = ports[state["port"]]
        device = current["device_id"]
        phase = state["phase"]
        packet = state["frame"]["packet"]
        if phase == "delivered":
            break
        if phase in {"localOutput", "ingress", "encapsulated"}:
            if phase == "ingress":
                local = any(packet["destination"] == encode(a["local"]) for i in interfaces.values() if i["device_id"] == device for a in i["addresses"] if a["family"] in ["inet", "inet6"])
                if local and devices[device]["role"] == "host":
                    require(accepts("INPUT"), "Destination INPUT denies witness")
                    state["phase"] = "localInput"
                    add("local", "«local»", "(by native_decide) (by native_decide)")
                    continue
                switches = [edge for edge in report["switches"] if edge[0] == state["port"]]
                switch = min(switches, key=lambda edge: distance_to_address(edge[1], next_hop or packet["destination"])) if switches else None
                if switch:
                    state["port"] = switch[1]
                    state["phase"] = "ready"
                    add("bridge", "bridge", "(by native_decide)")
                    continue
            routes = [r for r in report["routes"] if r[0] == state["port"] and r[2] <= packet["destination"] <= r[3]]
            require(routes, "No witness route at " + current["id"] + " to " + str(packet["destination"]))
            route = min(routes, key=lambda r: (r[6], -r[4], r[5]))
            route_index = report["routes"].index(route)
            next_hop = report["route_gateways"][route_index] or packet["destination"]
            state["port"] = route[1]
            state["phase"] = {"localOutput": "outputRouted", "ingress": "routed", "encapsulated": "ready"}[phase]
            add("route", {"localOutput": "routeLocalOutput", "ingress": "route", "encapsulated": "routeOuterPacket"}[phase], "⟨" + ", ".join(str(v) for v in route) + "⟩ (by native_decide) rfl")
        elif phase in {"routed", "outputRouted"}:
            require(accepts("FORWARD" if phase == "routed" else "OUTPUT"), "Filter denies witness at " + current["id"])
            state["phase"] = "filtered"
            add("filter", "filter" if phase == "routed" else "outputFilter", "(by native_decide)")
        elif phase == "filtered":
            candidates = selected(report["policies"][device]["out"], packet)
            if not candidates:
                state["phase"] = "ready"
                add("local", "forwardWithoutEncap", "(by native_decide)")
                continue
            association = candidates[0]
            sa = next((s for s in report["states"][device] if bound(association, s)), None)
            require(sa is not None, "Required SA missing")
            envelope = {"seal": [association[1], sa[1], sa[2], sa[3]], "header": copy.deepcopy(packet)}
            state["frame"]["encapLayers"].insert(0, envelope)
            packet.update({"source": association[2], "destination": association[3], "protocol": "esp", "sourcePort": 0, "destinationPort": 0, "matchedInboundPolicyIds": [], "matchedOutboundPolicyIds": [], "ipv4HeaderWords": 5 if association[2] < 2 ** 32 else 0, "ipv6NextHeader": 0 if association[2] < 2 ** 32 else 50})
            state["phase"] = "encapsulated"
            add("encrypt", "encrypt", association_list([association])[1:-1] + " " + tuple_list([sa])[1:-1] + " (by native_decide) (by native_decide) (by native_decide)")
        elif phase == "ready":
            edge = next((edge for edge in report["links"] if edge[0] == state["port"]), None)
            require(edge is not None, "No witness wire")
            state["port"] = edge[1]
            state["phase"] = "received"
            state["authenticated"] = []
            add("linkTransmit", "linkTransmit", "(by native_decide)")
        elif phase == "received":
            candidate = None
            if state["frame"]["encapLayers"]:
                envelope = state["frame"]["encapLayers"][0]
                for association in report["policies"][device]["in"]:
                    for sa in report["states"][device]:
                        if bound(association, sa) and envelope["seal"] == [association[1], sa[1], sa[2], sa[3]] and packet["source"] == association[2] and packet["destination"] == association[3] and packet["protocol"] == "esp" and matches(association, envelope["header"]):
                            candidate = (association, sa, envelope)
                            break
            state["phase"] = "ingress"
            state["frame"]["enteredIface"] = state["port"]
            if candidate:
                association, sa, envelope = candidate
                state["frame"]["encapLayers"].pop(0)
                header = copy.deepcopy(envelope["header"])
                state["frame"]["packet"] = copy.deepcopy(header)
                state["frame"]["packet"].update({"ingress": current["name"], "matchedInboundPolicyIds": [], "matchedOutboundPolicyIds": []})
                state["authenticated"] = [association[0]]
                rest = "[" + ", ".join("⟨⟨" + ", ".join(str(x) for x in e["seal"]) + "⟩, " + packet_lean(e["header"]) + "⟩" for e in state["frame"]["encapLayers"]) + "]"
                add("decrypt", "decrypt", association_list([association])[1:-1] + " " + tuple_list([sa])[1:-1] + " (" + packet_lean(header) + ") " + rest + " " + quoted(header["connectionState"]) + " (by native_decide) (by native_decide) (by native_decide) rfl rfl rfl rfl (by native_decide)")
            else:
                packet.update({"ingress": current["name"], "matchedInboundPolicyIds": [], "matchedOutboundPolicyIds": []})
                add("local", "receive", quoted(packet["connectionState"]))
        elif phase == "localInput":
            require(not state["frame"]["encapLayers"], "Delivery is not plaintext")
            state["phase"] = "delivered"
            destination_level = level(devices[device])
            add("deliver", "deliver", str(destination_level) + " (by native_decide) rfl")
        else:
            raise ValueError("Unexpected phase " + phase)
    require(state["phase"] == "delivered" and current["id"] == args.destination_port, "Witness did not reach destination")
    lines = ["import " + args.module, "", "namespace TDN.Deployments." + args.namespace, "open DataPlaneForwarding", "", "set_option maxRecDepth 1000000", "set_option maxHeartbeats 0", "set_option linter.unusedSimpArgs false", ""]
    for index, item in enumerate(states):
        lines.append("def witnessState" + str(index) + " : DataPlaneForwarding.State := ⟨" + str(item["port"]) + ", ." + item["phase"] + ", " + frame_lean(item["frame"]) + ", " + lean_list([str(x) for x in item["authenticated"]]) + "⟩")
    immediate_checks = []
    for index, item in enumerate(states):
        device_name = ports[item["port"]]["device_id"]
        gate = report.get("immediate_header_gates", {}).get(device_name)
        if gate is not None and item["phase"] in ["received", "localOutput", "encapsulated"]:
            packet = item["frame"]["packet"]
            if packet["source"] >= 2 ** 128:
                require(packet["ipv6NextHeader"] in gate, "Actual raw immediate-header gate rejects positive trace")
                immediate_checks.append("witnessState" + str(index) + ".frame.packet.ipv6NextHeader ∈ " +
                                        lean_list([str(value) for value in gate]))
    if immediate_checks:
        lines += ["", "lemma witness_immediate_header_checks : " +
                  " ∧ ".join(immediate_checks + ["True"]) + " := by native_decide"]
    for index, step in enumerate(steps):
        lines += ["", "lemma witnessStep" + str(index) + " : DataPlaneForwarding.Step config witnessState" + str(index) + " ." + step["action"] + " witnessState" + str(index + 1) + " := by", "  exact DataPlaneForwarding.Step." + step["constructor"] + " " + step["arguments"]]
    lines += ["", "def witnessActions : List Action := " + lean_list(["." + step["action"] for step in steps]), "", "theorem positive_delivery_forwarding : (lts config).MTr witnessState0 witnessActions witnessState" + str(len(steps)) + " := by", "  exact " + "(".join(["Cslib.LTS.MTr.stepL witnessStep" + str(i) + " " for i in range(len(steps))]) + "Cslib.LTS.MTr.refl" + ")" * (len(steps) - 1), "", "lemma witness_initial_stack : EncapStackConsistent config expectedEncapStack witnessState0 := by", "  unfold EncapStackConsistent ProcessingInvariant LocalAuthentication encapStackAfterIngress witnessState0 Frame.encapLayerIds config expectedEncapStack dataPlaneModelFromRecords expectedEncapStackFromRecords ifaceAt deviceAt ifaces devices", "  decide", "", "end TDN.Deployments." + args.namespace, ""]
    lines = [line.replace("(by native_decide)", "(by (try simp only [config, dataPlaneModelFromRecords, SelectedFibRoute, FibRoute.matches, accepts, saMatchesPolicy]); all_goals native_decide)") for line in lines]
    start = next(i for i, line in enumerate(lines) if line.startswith("lemma witness_initial_stack"))
    lines[start + 1:start + 3] = ["  exact ⟨⟨⟨rfl, rfl, Or.inl rfl, rfl⟩, rfl⟩, rfl⟩"]
    Path(args.output).write_text(forwarding_lean("\n".join(lines)))
    Path(args.trace).write_text(json.dumps({"source": args.source_port, "destination": args.destination_port, "states": states, "steps": steps}, indent=2) + "\n")
    print(json.dumps({"steps": len(steps), "encryption_steps": [i for i, s in enumerate(steps) if s["action"] == "encrypt"], "decryption_steps": [i for i, s in enumerate(steps) if s["action"] == "decrypt"]}))


if __name__ == "__main__":
    main()
