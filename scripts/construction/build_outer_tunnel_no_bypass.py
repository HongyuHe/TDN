"""Generate the RG030 shared delivery and SA-mode bindings from retained current inputs."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "data/evidence/outerTunnelNoBypass"

def read(relative):
    return json.loads((ROOT / relative).read_text())

def digest(relative):
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()

def build(profile):
    source_path = f"data/evidence/continuation/MtuSizing_{profile}.json"
    cohort = read(source_path)
    records = cohort["records"]
    network_by_host = {}
    endpoint_bindings = []
    for entry in cohort["sourceEntries"]:
        owner = records["nativeIfaces"][entry["hostIface"]]["owner"]
        assert records["ownerNames"][owner] == entry["sourceHost"]
        assert entry["sourceHost"] not in network_by_host
        network_by_host[entry["sourceHost"]] = entry
        endpoint_bindings.append(dict(host=entry["sourceHost"], owner=owner, hostIface=entry["hostIface"],
            sourceIface=entry["iface"], originalLevelId=records["nativeDevices"][owner]["ifaceSecurityDomain"],
            networkId=entry["originDomain"], network=entry["network"]))
    for owner, device in enumerate(records["nativeDevices"]):
        if device["ifaceSecurityDomain"] is not None:
            assert records["ownerNames"][owner] in network_by_host
    sample = read(f"data/evidence/continuation/Sizing{profile}Cases.json")["path"]
    prototype = read(f"data/evidence/continuation/Sizing{profile}Continuation.json")["moves"][0]
    defaults = copy.deepcopy(prototype["header"])
    header = copy.deepcopy(defaults)
    header.update(source=sample["flow"]["source"], destination=sample["flow"]["destination"], protocol="tcp",
                  sourcePort=53000, destinationPort=8080, connectionState="new", payloadBytes=[71,69,84,32,47,32,72,84,84,80],
                  networkBytes=50, ipv4FragmentOffset=0, hopLimit=64)
    nominal = copy.deepcopy(header)
    hidden = []
    layers = []
    iface = sample["flow"]["iface"]
    stage = "received"
    moves = []
    installations = cohort["installations"]
    fallback = installations[0]["installation"]
    def route_at(entry, destination, egress):
        matches = [r for r in records["routes"] if r["ingress"] == entry and r["egress"] == egress and r["destPrefixLow"] <= destination <= r["destPrefixHigh"]]
        return min(matches, key=lambda r: (-r["prefixLength"], r["tablePriority"], r["metric"]))
    def emit(operation, next_iface=None):
        nonlocal iface, stage, header, nominal
        step = copy.deepcopy(prototype)
        step.update(operation=operation, header=copy.deepcopy(header), next=next_iface if next_iface is not None else iface)
        source = receiver = fallback
        if operation == "route":
            step["route"] = route_at(iface, header["destination"], next_iface)
            iface = next_iface
            if stage == "encapsulated":
                stage = "egressReady"
            else:
                stage = "routed"
                header["hopLimit"] -= 1
        elif operation == "receive":
            stage = "ingress"
        elif operation == "forwardFilter":
            stage = "filtered"
        elif operation == "encryptIPsec":
            owner = records["nativeIfaces"][iface]["owner"]
            policy = next(p for p in records["nativeDevices"][owner]["egressPolicies"] if p["sourceLow"] <= header["source"] <= p["sourceHigh"] and p["destinationLow"] <= header["destination"] <= p["destinationHigh"])
            association = next(r["installation"]["association"] for r in installations if r["installation"]["device"] == owner and r["installation"]["direction"] == "outbound" and r["installation"]["association"]["reqid"] == policy["id"])
            step.update(policy=copy.deepcopy(policy), association=copy.deepcopy(association))
            hidden.append((copy.deepcopy(header), copy.deepcopy(nominal)))
            layers.append((copy.deepcopy(policy), copy.deepcopy(association)))
            header = copy.deepcopy(defaults)
            header.update(source=association["sender"], destination=association["receiver"], hopLimit=64)
            nominal = copy.deepcopy(header)
            nominal["hopLimit"] = 0
            stage = "encapsulated"
        elif operation == "decryptIPsec":
            old_policy, association = layers.pop()
            owner = records["nativeIfaces"][iface]["owner"]
            policy = next(p for p in records["nativeDevices"][owner]["ingressPolicies"] if p["id"] == association["reqid"] and p["sender"] == association["sender"] and p["receiver"] == association["receiver"])
            header, nominal = hidden.pop()
            step.update(policy=copy.deepcopy(policy), association=copy.deepcopy(association), header=copy.deepcopy(nominal))
            source = next(r["installation"] for r in installations if r["installation"]["direction"] == "outbound" and r["installation"]["association"] == association)
            receiver = next(r["installation"] for r in installations if r["installation"]["device"] == owner and r["installation"]["direction"] == "inbound" and r["installation"]["association"] == association)
            stage = "ingress"
        elif operation == "linkTransmit":
            assert [iface, next_iface] in records["links"]
            iface, stage = next_iface, "received"
        elif operation == "bridge":
            assert [iface, next_iface] in records["bridges"]
            iface, stage = next_iface, "egressReady"
        elif operation == "forwardWithoutEncap":
            stage = "egressReady"
        elif operation == "inputFilter":
            stage = "localInput"
        elif operation == "deliver":
            step["header"] = copy.deepcopy(nominal)
            stage = "delivered"
        domain = sample["flow"]["domain"]
        if operation == "deliver":
            owner = records["nativeIfaces"][iface]["owner"]
            endpoint = network_by_host[records["ownerNames"][owner]]
            assert any(interface["device"] == endpoint["sourceHost"] and interface.get("address") == header["destination"]
                       for interface in records["interfaces"])
            domain = endpoint["originDomain"]
        moves.append(dict(step=step, domain=domain, source=copy.deepcopy(source), receiver=copy.deepcopy(receiver)))
    if profile == "Baseline":
        for operation, next_iface in [
            ("receive",None),("route",57),("forwardFilter",None),("encryptIPsec",None),("route",57),
            ("linkTransmit",25),("bridge",27),("linkTransmit",106),("receive",None),("route",104),("forwardFilter",None),("encryptIPsec",None),("route",104),
            ("linkTransmit",83),("receive",None),("route",85),("forwardFilter",None),("forwardWithoutEncap",None),
            ("linkTransmit",4),("receive",None),("route",6),("forwardFilter",None),("forwardWithoutEncap",None),
            ("linkTransmit",97),("receive",None),("route",95),("forwardFilter",None),("forwardWithoutEncap",None),
            ("linkTransmit",116),("decryptIPsec",None),("route",118),("forwardFilter",None),("forwardWithoutEncap",None),
            ("linkTransmit",45),("bridge",43),("linkTransmit",69),("decryptIPsec",None),("route",73),("forwardFilter",None),("forwardWithoutEncap",None),
            ("linkTransmit",142),("receive",None),("inputFilter",None),("deliver",None)]:
            emit(operation,next_iface)
    else:
        for count in range(160):
            if stage == "received":
                bridges = [edge[1] for edge in records["bridges"] if edge[0] == iface]
                if bridges:
                    emit("bridge", bridges[0])
                    continue
                owner = records["nativeIfaces"][iface]["owner"]
                inbound = [r for r in installations if r["installation"]["device"] == owner and r["installation"]["direction"] == "inbound"]
                if layers and any(r["installation"]["association"] == layers[-1][1] for r in inbound):
                    emit("decryptIPsec")
                else:
                    emit("receive")
                if not layers and header["destination"] == sample["flow"]["destination"] and any(
                    interface["device"] == records["ownerNames"][owner] and interface.get("address") == header["destination"]
                    for interface in records["interfaces"]):
                    emit("inputFilter")
                    emit("deliver")
                    break
            if stage == "ingress":
                choices = [r for r in records["routes"] if r["ingress"] == iface and r["destPrefixLow"] <= header["destination"] <= r["destPrefixHigh"]]
                route = min(choices, key=lambda r: (-r["prefixLength"], r["tablePriority"], r["metric"]))
                emit("route", route["egress"])
                emit("forwardFilter")
                owner = records["nativeIfaces"][iface]["owner"]
                policies = [p for p in records["nativeDevices"][owner]["egressPolicies"] if p["sourceLow"] <= header["source"] <= p["sourceHigh"] and p["destinationLow"] <= header["destination"] <= p["destinationHigh"]]
                if policies:
                    emit("encryptIPsec")
                    choices = [r for r in records["routes"] if r["ingress"] == iface and r["destPrefixLow"] <= header["destination"] <= r["destPrefixHigh"]]
                    route = min(choices, key=lambda r: (-r["prefixLength"], r["tablePriority"], r["metric"]))
                    emit("route", route["egress"])
                else:
                    emit("forwardWithoutEncap")
            if stage == "egressReady":
                links = [edge[1] for edge in records["links"] if edge[0] == iface]
                assert links, (iface,stage)
                emit("linkTransmit", links[0])
        else:
            raise ValueError("The shared sample did not reach its Red destination")
    assert stage == "delivered" and not layers
    DEST.mkdir(parents=True,exist_ok=True)
    delivery = dict(source=source_path, sourceSHA256=digest(source_path), path=sample, moves=moves,
                    destinationEndpoint=endpoint_bindings[[binding["owner"] for binding in endpoint_bindings].index(records["nativeIfaces"][iface]["owner"])], endpointBindings=endpoint_bindings,
                    scope="Constructed TCP delivery through the November4 forwarding configuration with per-network recipient IDs derived from all imported Red host records; source/interface path and SA records are captured, modeled bytes are generated, no cross-capture packet identity is asserted.")
    (DEST / f"{profile}IPsecDelivery.json").write_text(json.dumps(delivery,indent=2,sort_keys=True)+"\n")
    bindings=[]
    for tunnel in records["tunnels"]:
        if tunnel["mechanism"] != "ipsec":
            continue
        owner=records["ownerNames"].index(tunnel["sender"])
        for record in installations:
            sa=record["installation"]
            if sa["device"] != owner or sa["direction"] != "outbound":
                continue
            observed=next(a for a in cohort["rawKeysBefore"]["associations"] if a["installationReference"] == sa["installation"])
            assert observed["mode"] == "tunnel" and observed["protocol"] == "esp"
            assert int(ipaddress.ip_address(observed["source"])) == sa["association"]["sender"]
            assert int(ipaddress.ip_address(observed["destination"])) == sa["association"]["receiver"]
            bindings.append(dict(tunnel=tunnel["id"],owner=owner,localIface=record["localIface"],
                                 association=sa["association"],installation=sa["installation"],
                                 mode=observed["mode"],protocol=observed["protocol"],observation=observed["publicStateObservation"],
                                 originalAssociatedIPTunnel=tunnel["associatedIPTunnel"],interpretedAssociatedIPTunnel=True,
                                 sourceHash=digest(source_path)))
    if profile == "Shared":
        (DEST / f"{profile}IPsecTunnelBindings.json").write_text(json.dumps(dict(bindings=bindings,source=source_path,sourceSHA256=digest(source_path)),indent=2,sort_keys=True)+"\n")
    print(json.dumps(dict(moves=len(moves),bindings=len(bindings),destination=str(DEST)),indent=2))

if __name__ == "__main__":
    for profile in ["Baseline", "Shared"]:
        build(profile)
