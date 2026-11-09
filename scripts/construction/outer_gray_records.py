"""Project MCP-exported native inventories and rule coverage records into typed JSON."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path


def level(name):
    return {"classification": name or "infrastructure", "compartments": [],
            "dissemination": [], "otherControls": []}


def project(bundle):
    sources = {record["id"]: record for record in bundle["sourceDevices"]}
    names = {value: key for key, value in bundle["deviceIds"].items()}
    bindings = {record["portId"]: record for record in bundle["ifaceBindings"]}
    interfaces = {record["id"]: record for record in bundle["sourceInterfaces"]}
    kinds = {"inner": "vpn", "outer": "vpn", "gray-firewall": "grayFirewall",
             "firewall": "outerFirewall", "host": "other", "switch": "ordinaryGraySwitch",
             "transport": "ordinaryGrayRouter"}
    devices = []
    for identity, record in sources.items():
        devices.append({"id": identity, "site": record["site"] or "transport",
                        "kind": kinds[record["role"]],
                        "layer": record["role"] if record["role"] in ["inner", "outer"] else None,
                        "level": level(record["security_level_id"]), "infrastructure": True})
    result_interfaces = []
    port_names = []
    policies = []
    scoped_local_addresses = []
    for port, native in enumerate(bundle["ports"]):
        binding = bindings[port]
        original = interfaces[binding["interfaceId"]]
        if names[native["owner"]] != binding["ownerDeviceId"]:
            raise ValueError("port ownership mismatch")
        if original["name"] != native["name"]:
            raise ValueError("native hook name mismatch")
        addresses = [int(ipaddress.ip_address(address["local"])) for address in original["addresses"]
                     if address["family"] == "inet" and address.get("scope") != "host"]
        if len(addresses) > 1:
            raise ValueError("multiple routable IPv4 addresses need an explicit interface expansion")
        namespace_addresses = [int(ipaddress.ip_address(address["local"])) +
                               (2**128 if address["family"] == "inet6" else 0)
                               for address in original["addresses"] if address["family"] in ["inet", "inet6"]]
        zone = binding["declaredZone"]
        if zone not in ["red", "gray", "black", "local"]:
            raise ValueError("unknown declared interface zone: " + str(zone))
        result_interfaces.append({"id": original["id"], "device": original["device_id"],
                                  "zone": zone, "address": addresses[0] if addresses else None,
                                  "namespaceAddresses": namespace_addresses,
                                  "linkAddress": None, "physical": binding["emulatedAttachment"],
                                  "externalData": binding["externalDataPort"],
                                  "managementNetwork": binding["managementNetwork"], "mtu": original["mtu"]})
        port_names.append(original["id"])
        scoped_local_addresses.append(addresses)
        device = bundle["devices"][native["owner"]]
        for hook, direction in [("input", "inbound"), ("output", "outbound"),
                                ("forward", "inbound"), ("forward", "outbound")]:
            if addresses:
                policies.append({"interface": original["id"], "direction": direction,
                                 "rules": device[hook + "Rules"], "defaultVerdict": device[hook + "Fallback"],
                                 "hook": hook})
    tunnels = []
    pairs = []
    seen_tunnels = set()
    for binding in bundle["ipsecTunnelBindings"]:
        if binding["tunnelId"] in seen_tunnels:
            continue
        seen_tunnels.add(binding["tunnelId"])
        sender, receiver = binding["senderDeviceId"], binding["receiverDeviceId"]
        current_layer = sources[sender]["role"]
        tunnels.append({"id": binding["tunnelId"], "layer": current_layer, "mechanism": "ipsec",
                        "sender": sender, "receiver": receiver,
                        "keyContext": "observed-session/" + binding["tunnelId"],
                        "espTunnelMode": True, "associatedIPTunnel": False})
        if current_layer == "inner":
            pairs.append({"endpoints": {"view": "internet", "source": sender, "destination": receiver,
                                        "sourceAddress": binding["seal"]["sender"],
                                        "destinationAddress": binding["seal"]["receiver"]},
                          "tunnel": binding["tunnelId"]})
    masks = []
    for owner, identity in names.items():
        if sources[identity]["role"] != "outer":
            continue
        program = bundle["devices"][owner]
        gray_mtu = min(binding["mtu"] for binding in bindings.values()
                       if binding["ownerId"] == owner and binding["declaredZone"] == "gray")
        for rule in program["forwardRules"]:
            if rule["verdict"] != "allow":
                continue
            fields = {}
            framing = []
            for atom in rule["atoms"]:
                if isinstance(atom, str):
                    framing.append(atom)
                else:
                    key, value = next(iter(atom.items()))
                    fields[key] = value
            source = fields["sourceRange"]
            destination = fields["destinationRange"]
            if source["low"] != source["high"] or destination["low"] != destination["high"]:
                raise ValueError("tunnel rule has non-singleton endpoints")
            for source_port in fields.get("sourcePorts", {"ports": [None]})["ports"]:
                for destination_port in fields.get("destinationPorts", {"ports": [None]})["ports"]:
                    mask = {"source": source["low"], "destination": destination["low"],
                            "protocol": fields["protocol"]["name"],
                            "ingress": fields["ingress"]["name"], "egress": fields["egress"]["name"],
                            "sourcePort": source_port, "destinationPort": destination_port,
                            "ipv4HeaderWords": fields.get("ipv4HeaderWords", {}).get("words"),
                            "matchedInboundPolicyIds": [fields["inboundPolicy"]["requestId"]] if "inboundPolicy" in fields else [],
                            "matchedOutboundPolicyIds": [fields["outboundPolicy"]["requestId"]] if "outboundPolicy" in fields else [],
                            "minimumBytes": 0, "maximumBytes": gray_mtu,
                            "requestFraming": "ipsecUDPFramingWithOptions" in framing,
                            "replyFraming": "ipsecUDPReplyFramingWithOptions" in framing}
                    masks.append({"owner": owner, "device": identity, "packet": mask})
    size_bindings = [{"iface": port, "policy": policy, "outerHeaderBytes": 20}
                     for port, native in enumerate(bundle["ports"])
                     for policy in bundle["devices"][native["owner"]]["egressPolicies"]]
    return {"components": devices, "interfaces": result_interfaces, "ifaceNames": port_names,
            "ownerNames": [names.get(index, "unlisted-device") for index in range(len(bundle["devices"]))],
            "policies": policies, "tunnels": tunnels, "pairs": pairs, "masks": masks,
            "ipsecSizes": size_bindings, "nativeDevices": bundle["devices"],
            "nativeIfaces": bundle["ports"], "routes": bundle["routes"], "links": bundle["links"],
            "bridges": bundle["bridges"], "rawBundle": bundle,
            "projection": {"kind": "namespace-boundary-addresses-v1",
                           "omittedAddresses": [{"interface": record["id"], "addresses": [address for address in record["addresses"]
                                                 if address.get("scope") == "host"]}
                                                for record in bundle["sourceInterfaces"] if any(address.get("scope") == "host" for address in record["addresses"])],
                           "allRawPortsPreserved": len(result_interfaces) == len(bundle["ports"]),
                           "allRawInterfacesPreserved": len(result_interfaces) == len(interfaces)}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    bundle = json.loads(args.source.read_text())
    result = project(bundle)
    result["records"] = {key: result.pop(key) for key in ["components", "interfaces", "ifaceNames", "ownerNames",
        "policies", "tunnels", "pairs", "masks", "ipsecSizes", "nativeDevices", "nativeIfaces", "routes", "links", "bridges"]}
    result["projection"]["sourceSHA256"] = hashlib.sha256(args.source.read_bytes()).hexdigest()
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    fields_path = args.destination.with_stem(args.destination.stem + "Fields")
    fields_path.write_text(json.dumps(result["records"], indent=2, sort_keys=True) + "\n")
    print(json.dumps({"source": str(args.source), "destination": str(args.destination),
                      "devices": len(result["records"]["components"]), "interfaces": len(result["records"]["interfaces"]),
                      "pairs": len(result["records"]["pairs"]), "masks": len(result["records"]["masks"])}))


if __name__ == "__main__":
    main()
