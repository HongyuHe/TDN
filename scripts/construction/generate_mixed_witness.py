"""Search actual imported operations, then have Lean check each useful transition."""
import argparse
from collections import deque
from copy import deepcopy
import json
from pathlib import Path
from network_names import forwarding_lean

from generate_execution_witness import atom_holds, bound, matches, packet_lean, selected
from import_execution import association_list, tuple_list
from import_family_execution import encode_address, render_rules
from import_snapshot import lean_list, quoted
from validate_evidence import require


def tup(values):
    return "⟨" + ", ".join(str(v) for v in values) + "⟩"


def policy_lean(policy):
    return association_list([policy])[1:-1]


def base_header(source, destination, protocol, sport=0, dport=0):
    return {"source": source, "destination": destination, "protocol": protocol,
            "ingress": "", "egress": "", "sourcePort": sport, "destinationPort": dport,
            "ipv4HeaderWords": 5 if source < 2**32 else 0,
            "ipv6NextHeader": 0 if source < 2**32 else (50 if protocol == "esp" else 17),
            "matchedInboundPolicyIds": [], "matchedOutboundPolicyIds": [], "connectionState": ""}


def visible(body):
    if body["kind"] == "datagram":
        return body["header"]
    if body["kind"] == "ipsec":
        seal = body["seal"]
        return base_header(seal[2], seal[3], "esp")
    if body["kind"] == "carrier":
        ep = body["endpoint"]
        return base_header(ep[0], ep[1], "udp", ep[2], ep[3])
    return None


def body_lean(body):
    kind = body["kind"]
    if kind in ["datagram", "ethernet"]:
        return "(." + kind + " " + packet_lean(body["header"]) + ")"
    if kind == "ipsec":
        value = tup(body["seal"])
    elif kind == "macsec":
        value = tup(body["association"])
    else:
        value = tup(body["endpoint"])
    return "(." + kind + " " + value + " " + body_lean(body["body"]) + ")"


def state_lean(state):
    return "{ iface := " + str(state["port"]) + ", datapathStage := ." + state["phase"] + \
           ", frame := { payload := 1, originDomain := 1, body := " + body_lean(state["body"]) + \
           " }, enteredIface := " + str(state["entered"]) + ", authenticated := " + \
           lean_list([str(v) for v in state["authenticated"]]) + ', tracking := "NEW" }'


CHECK = "(by (try simp only [config, MultiProtocolForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.dataPlaneModelFromRecords, DataPlaneForwarding.SelectedFibRoute, DataPlaneForwarding.FibRoute.matches, DataPlaneForwarding.accepts, DataPlaneForwarding.saMatchesPolicy, SameMACWireIdentity]); all_goals native_decide)"


def search(report, source="HA:red", destination="HB:red", ethernet=False, tags=None):
    data, ids = report["operational"], report["port_ids"]
    names = {v: k for k, v in ids.items()}
    owner = lambda port: names[port].split(":")[0]
    interface = lambda port: names[port].split(":")[1]
    addresses = lambda device: [encode_address(a[1]) for key, row in data["interfaces"].items()
                                if key.split(":")[0] == device for a in row["addresses"]]
    if ethernet:
        source_mac = int(data["interfaces"][source]["address"].replace(":", ""), 16)
        dest_mac = int(data["interfaces"][destination]["address"].replace(":", ""), 16)
        body = {"kind": "ethernet", "header": {"source": source_mac, "destination": dest_mac,
                "etherType": 0x88b5, "vlanTags": tags or []}}
    else:
        address = lambda key: encode_address(next(a[1] for a in data["interfaces"][key]["addresses"]
                                                  if a[0] == "inet"))
        body = {"kind": "datagram", "header": base_header(address(source), address(destination), "icmp")}
    start = {"port": ids[source], "phase": "ready" if ethernet else "localOutput",
             "body": body, "entered": ids[source], "authenticated": []}
    key = lambda s: json.dumps(s, sort_keys=True)
    pending = deque([start])
    history = {key(start): None}
    states_by_key = {key(start): start}

    def transitions(s):
        port, phase, body = s["port"], s["phase"], s["body"]
        device, header = owner(port), visible(body)

        def emit(action, proof, **changes):
            return action, proof, s | changes

        def accepts(hook):
            p = header | {"ingress": interface(s["entered"]), "egress": interface(port),
                          "matchedInboundPolicyIds": s["authenticated"],
                          "matchedOutboundPolicyIds": [a[0] for a in selected(data["policies"][device]["out"], header)],
                          "connectionState": "NEW"}
            for family in ["4", "6"]:
                for rule in data["hooks"][device][family][hook]["parsed_rules"]:
                    if all(atom_holds(atom, p) for atom in rule["atoms"]):
                        return rule["verdict"] == "allow"
            return False

        if phase in ["localOutput", "ingress", "encapsulated"] and header:
            candidates = [r for r in data["routes"] if r["device"] == device and
                          r["low"] <= header["destination"] <= r["high"]]
            rank = lambda r: (r["priority"], -r["prefix"], r["metric"])
            for route in candidates:
                if rank(route) != min(map(rank, candidates)):
                    continue
                row = [port, ids[route["egress"]], route["low"], route["high"],
                       route["prefix"], route["metric"], route["priority"]]
                constructor, next_phase = {"localOutput": ("routeLocalOutput", "outputRouted"),
                    "ingress": ("route", "routed"), "encapsulated": ("routeOuterPacket", "ready")}[phase]
                yield emit("route", "MultiProtocolForwarding.Step." + constructor + " " + tup(row) +
                           " rfl rfl " + CHECK + " rfl", port=row[1], phase=next_phase)
            if phase == "ingress" and header["destination"] in addresses(device) and accepts("INPUT"):
                yield emit("inputFilter", "MultiProtocolForwarding.Step.inputFilter rfl rfl " + CHECK + " " + CHECK,
                           phase="localInput")
        if phase in ["routed", "outputRouted"] and header:
            hook = "FORWARD" if phase == "routed" else "OUTPUT"
            constructor = "forwardFilter" if phase == "routed" else "outputFilter"
            if accepts(hook):
                yield emit(constructor, "MultiProtocolForwarding.Step." + constructor + " rfl rfl " + CHECK, phase="filtered")
        if phase == "filtered" and header:
            policies = selected(data["policies"][device]["out"], header)
            if not policies:
                yield emit("forwardWithoutEncap", "MultiProtocolForwarding.Step.forwardWithoutEncap rfl rfl " + CHECK, phase="ready")
            for policy in policies:
                for association in data["states"][device]:
                    if bound(policy, association):
                        seal = [policy[1], association[1], association[2], association[3]]
                        yield emit("encryptIPsec", "MultiProtocolForwarding.Step.encryptIPsec " + policy_lean(policy) + " " +
                                   tup(association) + " rfl rfl " + " ".join([CHECK]*3),
                                   phase="encapsulated", body={"kind": "ipsec", "seal": seal, "body": body})
        if phase == "received":
            if header:
                yield emit("receive", 'Step.receive rfl rfl "NEW"', phase="ingress",
                           entered=port, authenticated=[])
            if body["kind"] == "ipsec" and visible(body["body"]):
                for policy in data["policies"][device]["in"]:
                    for association in data["states"][device]:
                        seal = [policy[1], association[1], association[2], association[3]]
                        if bound(policy, association) and seal == body["seal"] and matches(policy, visible(body["body"])):
                            yield emit("decryptIPsec", "MultiProtocolForwarding.Step.decryptIPsec " + policy_lean(policy) + " " +
                                tup(association) + " " + body_lean(body["body"]) + " " +
                                packet_lean(visible(body["body"])) + " rfl rfl " +
                                " ".join([CHECK]*3) + ' rfl ' + CHECK + ' "NEW"',
                                phase="ingress", body=body["body"], entered=port, authenticated=[policy[0]])
            if body["kind"] == "ethernet" and report["devices"][device]["role"] == "host":
                yield emit("deliver", "MultiProtocolForwarding.Step.deliverEthernet " + packet_lean(body["header"]) +
                           " 1 rfl rfl rfl", phase="delivered")
        if phase == "localInput":
            if body["kind"] == "datagram" and report["devices"][device]["role"] == "host":
                yield emit("deliver", "MultiProtocolForwarding.Step.deliver 1 rfl rfl rfl", phase="delivered")
            if body["kind"] == "carrier":
                ep = body["endpoint"]
                for index, carrier in enumerate(data["carriers"]):
                    expected = [encode_address(carrier["destination"]), encode_address(carrier["source"]),
                                carrier["destination_port"], carrier["source_port"], carrier["local_session"]]
                    if carrier["device"] == device and ep == expected:
                        expression = "(carriers[" + str(index) + "]'(by native_decide))"
                        yield emit("decapsulate", "MultiProtocolForwarding.Step.decapsulate " + expression + " " +
                                   body_lean(body["body"]) + " " + CHECK + " rfl rfl rfl",
                                   port=ids[device + ":" + carrier["interface"]], phase="received",
                                   body=body["body"], authenticated=[])
        if phase in ["received", "ready"]:
            for a, b in data["bridges"]:
                if ids[a] == port:
                    constructor = "bridge" if phase == "received" else "bridgeOutput"
                    yield emit("bridge", "MultiProtocolForwarding.Step." + constructor + " " + str(ids[b]) + " rfl " + CHECK,
                               port=ids[b], phase="ready")
        if phase == "ready":
            for a, b in data["links"]:
                if ids[a] == port:
                    yield emit("linkTransmit", "MultiProtocolForwarding.Step.linkTransmit " + str(ids[b]) + " rfl " + CHECK,
                               port=ids[b], phase="received", authenticated=[])
            for index, mac in enumerate(data["mac_ports"]):
                if ids[mac["device"] + ":" + mac["logical"]] == port:
                    assoc = [mac["tag"], mac["tx_sci"], mac["tx_an"], 0]
                    expression = "(macIfaces[" + str(index) + "]'(by native_decide))"
                    yield emit("encryptMACsec", "MultiProtocolForwarding.Step.encryptMACsec " + expression + " " + tup(assoc) +
                               " " + CHECK + " rfl rfl ⟨rfl, rfl⟩",
                               port=ids[mac["device"] + ":" + mac["physical"]],
                               body={"kind": "macsec", "association": assoc, "body": body})
            for index, carrier in enumerate(data["carriers"]):
                if ids[carrier["device"] + ":" + carrier["interface"]] == port:
                    anchors = [ids[k] for k, row in data["interfaces"].items()
                               if k.startswith(device + ":") and
                               any(a[1] == carrier["source"] for a in row["addresses"])]
                    require(len(anchors) == 1, "Carrier routing anchor")
                    ep = [encode_address(carrier["source"]), encode_address(carrier["destination"]),
                          carrier["source_port"], carrier["destination_port"], carrier["peer_session"]]
                    yield emit("encapsulate", "MultiProtocolForwarding.Step.encapsulate (carriers[" + str(index) + "]'(by native_decide)) " +
                               CHECK + " rfl rfl", port=anchors[0], entered=anchors[0],
                               authenticated=[], phase="localOutput",
                               body={"kind": "carrier", "endpoint": ep, "body": body})
        if phase == "received" and body["kind"] == "macsec":
            for index, mac in enumerate(data["mac_ports"]):
                if ids[mac["device"] + ":" + mac["physical"]] == port:
                    assoc = [mac["tag"], mac["rx_sci"], mac["rx_an"], 0]
                    if assoc[1:3] == body["association"][1:3]:
                        expression = "(macIfaces[" + str(index) + "]'(by native_decide))"
                        yield emit("decryptMACsec", "MultiProtocolForwarding.Step.decryptMACsec " + expression + " " +
                                   tup(assoc) + " " + tup(body["association"]) + " " +
                                   body_lean(body["body"]) + " " + CHECK + " rfl rfl rfl " +
                                   CHECK + " " + CHECK, port=ids[mac["device"] + ":" + mac["logical"]],
                                   body=body["body"], authenticated=[])

    finish = None
    while pending:
        state = pending.popleft()
        if state["port"] == ids[destination] and state["phase"] == "delivered":
            finish = key(state)
            break
        require(len(history) < 20000, "Useful trace search exceeded diagnostic state bound")
        for action, proof, after in transitions(state):
            encoded = key(after)
            if encoded in history:
                continue
            history[encoded] = (key(state), action, proof)
            states_by_key[encoded] = after
            pending.append(after)
    require(finish is not None, "No modeled delivery: explored " + str(len(history)) + " states")
    states, actions, proofs = [], [], []
    cursor = finish
    while cursor is not None:
        states.append(states_by_key[cursor])
        parent = history[cursor]
        if parent is None:
            break
        cursor, action, proof = parent
        actions.append(action)
        proofs.append(proof)
    return list(reversed(states)), list(reversed(actions)), list(reversed(proofs))



def bridge_observations(report, states, actions):
    data, ids = report["operational"], report["port_ids"]
    names = {v: k for k, v in ids.items()}

    def ethernet_header(body):
        if body["kind"] == "ethernet":
            return body["header"]
        require(body["kind"] == "macsec", "Positive bridge path needs explicit Ethernet body")
        if visible(body["body"]) is None:
            inner = ethernet_header(body["body"])
            source, destination = inner["source"], inner["destination"]
        else:
            association = body["association"]
            senders = [m for m in data["mac_ports"] if m["tx_sci"] == association[1] and m["tx_an"] == association[2]]
            receivers = [m for m in data["mac_ports"] if m["rx_sci"] == association[1] and m["rx_an"] == association[2]]
            require(len(senders) == len(receivers) == 1, "Positive Ethernet peer binding ambiguous")
            mac = lambda m: int(data["interfaces"][m["device"] + ":" + m["physical"]]["address"].replace(":", ""), 16)
            source, destination = mac(senders[0]), mac(receivers[0])
        return {"source": source, "destination": destination, "etherType": 0x88e5, "vlanTags": []}

    checks = []
    for index, action in enumerate(actions):
        if action != "bridge":
            continue
        before, after = states[index:index+2]
        first, last = names[before["port"]], names[after["port"]]
        device, ingress = first.split(":")
        other, egress = last.split(":")
        require(device == other and data["interfaces"][first].get("master") and
                data["interfaces"][first]["master"] == data["interfaces"][last].get("master"),
                "Useful bridge transfer must directly connect two actual bridge members")
        header = ethernet_header(before["body"])
        protocol = header["vlanTags"][0] // 65536 if header["vlanTags"] else header["etherType"]
        packet = base_header(header["source"], header["destination"], str(protocol))
        packet.update(ingress=ingress, egress=egress)
        rules = data["bridge_filters"][device]
        verdict = next(r["verdict"] for r in rules if all(atom_holds(a, packet) for a in r["atoms"]))
        require(verdict == "allow", "Positive bridge transfer is denied by actual rules")
        checks.append({"step": index, "device": device, "rules": rules, "packet": packet})
    return checks

def render(report, module, ethernet=False, tags=None, reverse=False, label=""):
    source, destination = ("HB:red", "HA:red") if reverse else ("HA:red", "HB:red")
    states, actions, proofs = search(report, source, destination, ethernet=ethernet, tags=tags)
    bridge_checks = bridge_observations(report, states, actions)
    ns = "TDN.Deployments." + report["namespace"] + ("." + label if label else "")
    lines = ["import " + module, "", "namespace " + ns,
             "open MultiProtocolForwarding LayeredFrame", "set_option maxRecDepth 1000000",
             "set_option maxHeartbeats 0", "set_option linter.unusedSimpArgs false", ""]
    for i, state in enumerate(states):
        lines.append("def usefulState" + str(i) + " : MultiProtocolForwarding.State := " + state_lean(state))
    for i, (action, proof) in enumerate(zip(actions, proofs)):
        lines += ["", "lemma usefulStep" + str(i) + " : MultiProtocolForwarding.Step config usefulState" + str(i) +
                  " ." + action + " usefulState" + str(i+1) + " := by", "  exact " + proof]
    for check in bridge_checks:
        index = check["step"]
        lines += ["", "def bridgeRules" + str(index) + " : List PacketPolicy.Rule := " + render_rules(check["rules"]),
                  "def bridgePacket" + str(index) + " : PacketPolicy.Packet := " + packet_lean(check["packet"]),
                  "lemma positive_bridge_filter" + str(index) + " : DataPlaneForwarding.accepts bridgeRules" + str(index) +
                  " .deny bridgePacket" + str(index) + " := by",
                  "  unfold DataPlaneForwarding.accepts bridgeRules" + str(index) + " bridgePacket" + str(index) + "; decide"]
    lines += ["", "def usefulActions : List MultiProtocolForwarding.Action := " +
              lean_list(["." + action for action in actions]), "",
              "theorem positive_mixed_delivery : (lts config).MTr usefulState0 usefulActions usefulState" +
              str(len(actions)) + " := by", "  exact " +
              "".join("Cslib.LTS.MTr.stepL usefulStep" + str(i) + " (" for i in range(len(actions))) +
              "Cslib.LTS.MTr.refl" + ")"*len(actions), "",
              "lemma useful_red_origin : Requirements.MixedRedOrigin redSources usefulState0 := by",
              "  simp [Requirements.MixedRedOrigin, usefulState0, redSources]",
              "", "lemma useful_plaintext_delivery : usefulState" + str(len(actions)) + ".datapathStage = .delivered ∧",
              "    usefulState" + str(len(actions)) + ".frame.body.protectionLayers = [] := ⟨rfl, rfl⟩",
              "end " + ns, ""]
    return forwarding_lean("\n".join(lines)), {"states": states, "actions": actions, "bridge_checks": bridge_checks,
                              "scope": "Checked model delivery establishes useful behavior in the recorded model. Live probes independently establish actual payload delivery; drop-only omitted bridge checks require separate positive correspondence."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--ethernet", action="store_true")
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    content, trace = render(report, args.module, args.ethernet)
    args.output.write_text(content)
    args.trace.write_text(json.dumps(trace, indent=2) + "\n")
    print(report["namespace"], len(trace["actions"]), "checked-step candidates")
