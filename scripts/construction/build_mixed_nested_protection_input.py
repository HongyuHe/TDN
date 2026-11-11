import argparse
import copy
import hashlib
import json
from pathlib import Path


def only(values, meaning):
    values = list(values)
    if len(values) != 1:
        raise ValueError((meaning, len(values)))
    return values[0]


def atom(record):
    kind = record["kind"]
    if kind in {"sourceRange", "destinationRange"}:
        return {kind: {"low": record["low"], "high": record["high"]}}
    if kind == "protocol":
        return {"etherTypes": {"values": [int(record["value"], 0)]}}
    if kind in {"ingress", "egress"}:
        return {kind: {"name": record["value"]}}
    raise ValueError(record)


def octets(value, width):
    return list(value.to_bytes(width, "big"))


def build(path):
    raw = json.loads(path.read_text())
    execution = raw["execution"]
    devices = copy.deepcopy(execution["devices"])
    ports = execution["ports"]
    owner_names = raw["ownerNames"]
    owner_ids = {name: index for index, name in enumerate(owner_names)}
    for binding in raw["hostNetworkIdBindings"]:
        devices[binding["owner"]]["ifaceSecurityDomain"] = binding["networkId"]
    for component in raw["components"]:
        if component["layer"] in {"inner", "outer"}:
            if not component["infrastructure"]:
                raise ValueError("Transit encryptor infrastructure interpretation is required")
    address_owner = {interface["address"]: interface["device"] for interface in raw["interfaces"] if interface["address"] is not None}
    tunnels = []
    ipsec_tunnel_bindings = []
    macsec_tunnel_bindings = []
    for record in raw["installations"]:
        installation = record["installation"]
        if installation["direction"] != "outbound":
            continue
        association = installation["association"]
        policy = only((policy for policy in devices[installation["device"]]["egressPolicies"] if policy["id"] == association["reqid"] and policy["sender"] == association["sender"] and policy["receiver"] == association["receiver"]), "outgoing IPsec policy")
        sender, receiver = address_owner[association["sender"]], address_owner[association["receiver"]]
        name = "ipsec:" + sender + "->" + receiver + ":" + str(association["spi"])
        stamp = {"tag": policy["tag"], "association": association["spi"], "sender": association["sender"], "receiver": association["receiver"]}
        tunnels.append({"id": name, "layer": "inner", "mechanism": "ipsec", "sender": sender, "receiver": receiver, "keyContext": "ipsec:" + record["materialReference"], "espTunnelMode": True, "associatedIPTunnel": True})
        ipsec_tunnel_bindings.append([stamp, name])
    mac_materials = [[record["association"], record["materialReference"]] for record in execution["macsecKeyBindings"]]
    static_peers = []
    for iface in execution["macIfaces"]:
        association = iface["transmitAssociation"]
        peer = only((peer for peer in raw["macsecPeerEndpoints"] if peer["sourceIface"] == iface["physicalIface"] and peer["actorSCI"] == association["sci"]), "static MACsec peer")
        sender = owner_names[ports[peer["sourceIface"]]["owner"]]
        receiver = owner_names[ports[peer["destinationIface"]]["owner"]]
        name = "macsec:" + sender + "->" + receiver + ":" + str(association["sci"])
        material = only((material for current, material in mac_materials if current == association), "MACsec material reference")
        tunnels.append({"id": name, "layer": "outer", "mechanism": "macsec", "sender": sender, "receiver": receiver, "keyContext": "macsec:" + material, "espTunnelMode": False, "associatedIPTunnel": False})
        macsec_tunnel_bindings.append([association, name])
        static_peers.append(dict(peer, tunnel=name))
    contexts = []
    inner_outer_uses = []
    for source in raw["sourceEntries"]:
        owner = ports[source["iface"]]["owner"]
        selected_tunnel = only((tunnel for tunnel in tunnels if tunnel["layer"] == "inner" and tunnel["sender"] == owner_names[owner]), "Inner directional tunnel")
        stamp = only((stamp for stamp, name in ipsec_tunnel_bindings if name == selected_tunnel["id"]), "Inner stamp")
        destination = only((entry for entry in raw["sourceEntries"] if selected_tunnel["receiver"] == owner_names[ports[entry["iface"]]["owner"]]), "destination Red network")
        source_site = only((network["site"] for network in raw["networks"] if network["id"] == source["network"]), "source site")
        outer = only((component for component in raw["components"] if component["site"] == source_site and component["layer"] == "outer"), "local Outer")
        outer_tunnel = only((tunnel for tunnel in tunnels if tunnel["layer"] == "outer" and tunnel["sender"] == outer["id"]), "Outer directional tunnel")
        outer_association = only((association for association, name in macsec_tunnel_bindings if name == outer_tunnel["id"]), "Outer association")
        destination_mac = only((iface for iface in execution["macIfaces"] if owner_names[ports[iface["physicalIface"]]["owner"]] == outer_tunnel["receiver"]), "destination logical interface")
        policy = only((policy for policy in devices[owner]["egressPolicies"] if policy["sender"] == stamp["sender"] and policy["receiver"] == stamp["receiver"]), "directional selector")
        contexts.append({"flow": {"sourceNetwork": source["network"], "destinationNetwork": destination["network"], "innerTunnel": selected_tunnel["id"], "outerTunnel": outer_tunnel["id"]}, "originDomain": source["originDomain"], "sourceInnerOwner": owner, "sourceHostOwner": ports[source["hostIface"]]["owner"], "destinationInnerOwner": ports[destination["iface"]]["owner"], "destinationHostOwner": ports[destination["hostIface"]]["owner"], "innerStamp": stamp, "outerAssociation": outer_association, "destinationLogicalIface": destination_mac["logicalIface"], "remoteLow": policy["destinationLow"], "remoteHigh": policy["destinationHigh"]})
        inner_outer_uses.append([selected_tunnel["sender"], outer_tunnel["sender"]])
    sizes = [{"iface": index, "policy": policy, "outerHeaderBytes": 20} for index in range(1, len(ports)) for policy in devices[ports[index]["owner"]]["egressPolicies"]]
    link_policies = []
    bridge_rules = []
    for owner, rules in execution["operational"]["bridge_filters"].items():
        for rule in rules:
            bridge_rules.append({"owner": owner_ids[owner], "rule": {"atoms": [atom(item) for item in rule["atoms"]], "verdict": rule["verdict"]}})
    path_ifaces = {iface["physicalIface"] for iface in execution["macIfaces"]}
    path_ifaces.update(index for edge in execution["bridges"] for index in edge)
    for index in sorted(path_ifaces):
        owner = owner_names[ports[index]["owner"]]
        name = ports[index]["name"]
        programs = []
        for side in ["ingress", "egress"]:
            rules = []
            for rule in execution["operational"]["bridge_filters"][owner]:
                current = [item for item in rule["atoms"] if item["kind"] == side]
                if current and current[0]["value"] != name:
                    continue
                atoms = [atom(item) for item in rule["atoms"] if item["kind"] not in {"ingress", "egress"}]
                rules.append({"atoms": atoms, "verdict": rule["verdict"]})
            programs.append({"rules": rules, "fallback": "deny"})
        link_policies.append([index, {"inbound": programs[0], "outbound": programs[1]}])
    frames = []
    for association, name in macsec_tunnel_bindings:
        source_mac = association["sci"] // 65536
        destination_mac = only((other["sci"] // 65536 for other, other_name in macsec_tunnel_bindings if other_name != name), "peer MAC address")
        header = {"source": source_mac, "destination": destination_mac, "etherType": 35045, "vlanTags": []}
        payload = [40 + association["associationNumber"], 0] + [0, 0, 0, 1] + octets(association["sci"], 8) + [0] * 16
        frames.append([association, {"header": header, "headerBytes": octets(destination_mac, 6) + octets(source_mac, 6) + octets(35045, 2), "payload": payload}])
    return {"records": {"ownerNames": owner_names, "ifaceNames": raw["ifaceNames"], "deviceData": devices, "ifaceData": ports, "components": raw["components"], "interfaces": raw["interfaces"], "networks": raw["networks"], "entries": raw["sourceEntries"], "attachments": raw["redNetworkAttachments"], "sourceFlows": raw["sourceFlows"], "routes": execution["routes"], "links": execution["links"], "bridges": execution["bridges"], "macIfaces": execution["macIfaces"], "staticPeers": static_peers, "ipsecSizes": sizes, "installations": raw["installations"], "epoch": only({record["installation"]["epoch"] for record in raw["installations"]}, "fixed epoch"), "tunnels": tunnels, "ipsecTunnelBindings": ipsec_tunnel_bindings, "macsecTunnelBindings": macsec_tunnel_bindings, "macMaterials": mac_materials, "macFrames": frames, "linkPolicies": link_policies, "bridgeRules": bridge_rules, "contexts": contexts, "innerOuterUses": inner_outer_uses, "authentication": [{"device": record["device"], "certificateAuth": record["certificateAuth"], "pskAuth": record["pskAuth"]} for record in raw["authentication"]]}, "rawInventory": raw, "provenance": {"input": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "interpretation": "Corrected per-network host IDs; transit-gateway infrastructure derived by source-bound inventory projection; directional tunnel IDs from actual SA/SCI peers; opaque constructed MACsec framing representatives carry no ciphertext transformation claim; two-sided bridge programs retain the original two allowed data edges."}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("data/evidence/nestedProtection/exports/v32-mixed-ipsec-macsec-inventory-r3-mixed_deployment_inventory.json"))
    parser.add_argument("--output", type=Path, default=Path("data/evidence/nestedProtection/MixedIPsecMACsec.json"))
    args = parser.parse_args()
    result = build(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
