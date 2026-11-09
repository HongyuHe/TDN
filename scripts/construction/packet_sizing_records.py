"""Normalize aligned native, public-SA and full-frame sizing observations."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path

from outer_gray_records import project, level


RECORD_KEYS = ["components", "interfaces", "ifaceNames", "ownerNames", "policies", "tunnels",
               "pairs", "masks", "ipsecSizes", "nativeDevices", "nativeIfaces", "routes", "links", "bridges"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def state_signature(row):
    return (row["reqid"], row["spi"], int(ipaddress.ip_address(row["source"])),
            int(ipaddress.ip_address(row["destination"])))


def public_signature(row):
    return (row["device"], row["direction"], *state_signature(row))


def stable_material(row):
    return (row["installationReference"], row["keyBits"], row["saltBytes"], row["icvBits"],
            tuple((part["kind"], part["algorithm"], part["bytes"], part["parameters"], part["sha256"])
                  for part in row["materials"]))


def key_records(bundle, before, after, epoch):
    first = {public_signature(row): row for row in before["associations"]}
    last = {public_signature(row): row for row in after["associations"]}
    if len(first) != len(before["associations"]) or len(last) != len(after["associations"]):
        raise ValueError("duplicate public SA direction binding")
    if set(first) != set(last):
        raise ValueError("public SA cohort changed")
    if any(stable_material(first[key]) != stable_material(last[key]) for key in first):
        raise ValueError("SA installation or private material reference changed")
    result = []
    used = set()
    for name, owner in bundle["deviceIds"].items():
        device = bundle["devices"][owner]
        for state in device["states"]:
            signature = (state["reqid"], state["spi"], state["sender"], state["receiver"])
            matches = [row for row in first.values() if row["device"] == name and state_signature(row) == signature]
            if len(matches) != 1:
                raise ValueError("raw SAD state lacks one observed direction")
            row = matches[0]
            policies = device["ingressPolicies" if row["direction"] == "inbound" else "egressPolicies"]
            if not any(policy["id"] == state["reqid"] and
                       policy["sender"] == state["sender"] and policy["receiver"] == state["receiver"] and
                       (policy["requiredSpi"] is None or policy["requiredSpi"] == state["spi"]) for policy in policies):
                raise ValueError("observed SA direction lacks an endpoint/policy binding")
            if row["keyBits"] != 256 or row["saltBytes"] != 4 or row["icvBits"] != 128 or len(row["materials"]) != 1:
                raise ValueError("unsupported native ESP transform")
            material = row["materials"][0]
            if material["kind"] != "aead" or material["algorithm"] != "rfc4106(gcm(aes))" or material["bytes"] != 36:
                raise ValueError("unsupported private material descriptor")
            peer = [other for other in first.values() if other["device"] == row["peerDevice"] and
                    other["direction"] != row["direction"] and state_signature(other) == signature]
            if len(peer) != 1 or peer[0]["materials"] != row["materials"]:
                raise ValueError("SA peer/key equality binding is incomplete")
            local_port = bundle["portIds"].get(name + ":" + row["localInterface"])
            if local_port is None:
                raise ValueError("public SA local interface is absent from native capture")
            result.append({"localIface": local_port, "installation": {"device": owner, "direction": row["direction"], "association": state,
                                     "epoch": epoch, "installation": row["installationReference"]},
                           "deviceName": name, "localInterface": row["localInterface"],
                           "materialReference": material["sha256"], "peerDevice": bundle["deviceIds"][row["peerDevice"]],
                           "keyBits": row["keyBits"], "saltBytes": row["saltBytes"], "icvBits": row["icvBits"],
                           "sourceObservation": row["publicStateObservation"],
                           "materialObservation": row["materialObservation"],
                           "beforePublicId": row["id"], "afterPublicId": last[public_signature(row)]["id"]})
            used.add(public_signature(row))
    if used != set(first):
        raise ValueError("public SA inventory is not completely represented by raw SAD")
    return result


def source_records(bundle):
    bindings = {row["portId"]: row for row in bundle["ifaceBindings"]}
    devices = {row["id"]: row for row in bundle["sourceDevices"]}
    edges = bundle["links"] + bundle["bridges"]
    result = []
    networks = []
    attachments = []
    for source in bundle["sourceAttachments"]:
        frontier = [[source["portId"]]]
        seen = set()
        targets = []
        while frontier:
            path = frontier.pop(0)
            port = path[-1]
            if port in seen:
                continue
            seen.add(port)
            binding = bindings[port]
            if binding["declaredRole"] == "inner" and binding["declaredZone"] == "red":
                targets.append((port, path))
                continue
            frontier.extend(path + [right] for left, right in edges if left == port and right not in seen)
        if len(targets) != 1:
            raise ValueError("declared Red source needs one recorded Inner attachment path")
        port, path = targets[0]
        binding = bindings[port]
        device = devices[binding["ownerDeviceId"]]
        if device["site"] != source["site"] or device["security_level_id"] != source["securityLevelId"]:
            raise ValueError("Red attachment changes owner/site/security level")
        identity = binding["ownerDeviceId"] + "/red-network"
        if any(row["id"] == identity for row in networks):
            raise ValueError("multiple Red sources need an explicit shared-network interpretation")
        domain = len(networks) + 1
        networks.append({"id": identity, "site": source["site"], "level": level(source["securityLevelId"]),
                         "innerComponents": [binding["ownerDeviceId"]]})
        result.append({"iface": port, "network": identity, "originDomain": domain,
                       "sourceHost": source["deviceId"], "hostIface": source["portId"], "arrivalPath": path})
        attachments.extend({"network": identity, "interface": bindings[endpoint]["interfaceId"]}
                           for endpoint in [source["portId"], port])
    expected = {row["portId"] for row in bindings.values()
                if row["declaredRole"] == "inner" and row["declaredZone"] == "red" and not row["managementNetwork"]}
    if {row["iface"] for row in result} != expected or not result:
        raise ValueError("recorded source paths do not cover every Inner Red attachment")
    return networks, result, attachments


def sizing_roles(bundle):
    result = []
    for row in bundle["ifaceBindings"]:
        role = "other"
        if row["declaredRole"] == "inner" and row["declaredZone"] == "gray":
            role = "innerExternal"
        elif row["declaredRole"] == "outer" and row["declaredZone"] == "black":
            role = "grayFirewallOrEncryptionExternal"
        elif row["declaredRole"] == "gray-firewall" and row["declaredZone"] == "gray" and row["emulatedAttachment"] and not row["managementNetwork"]:
            role = "grayFirewallOrEncryptionExternal"
        result.append({"iface": row["portId"], "interface": row["interfaceId"], "owner": row["ownerId"],
                       "device": row["ownerDeviceId"], "declaredRole": row["declaredRole"],
                       "declaredZone": row["declaredZone"], "linkKind": row["linkKind"],
                       "attached": row["emulatedAttachment"], "managementNetwork": row["managementNetwork"],
                       "originalExternalData": row["externalDataPort"], "mtu": row["mtu"], "role": role})
    for name, owner in bundle["deviceIds"].items():
        if any(row["ownerId"] == owner and row["declaredRole"] == "gray-firewall" for row in bundle["ifaceBindings"]):
            if not any(row["owner"] == owner and row["role"] == "grayFirewallOrEncryptionExternal" for row in result):
                raise ValueError("Gray firewall has no attached Gray data sizing interface")
    return sorted(result, key=lambda row: row["iface"])


def bridge_records(native, bridge):
    if bridge["deviceIds"] != native["deviceIds"] or bridge["portIds"] != native["portIds"]:
        raise ValueError("bridge/native identity numbering differs")
    pairs = [pair for switch in bridge["switches"] for pair in switch["possibleSwitching"]]
    if sorted(pairs) != sorted(native["bridges"]):
        raise ValueError("bridge/native bridging coverage differs")
    endpoints = []
    policies = []
    for switch in bridge["switches"]:
        if switch["nftInventory"]["absentLinkFamilies"] != ["bridge", "netdev"]:
            raise ValueError("observed bridge/netdev program requires explicit support")
        for row in switch["ovsTables"]["port"]:
            if any(row[key] != ["set", []] for key in ["tag", "trunks", "vlan_mode", "bond_mode"]):
                raise ValueError("OVS VLAN/bond configuration requires explicit transformation support")
        for endpoint in switch["ports"]:
            port = endpoint["portId"]
            if native["ports"][port]["owner"] != endpoint["ownerId"]:
                raise ValueError("bridge endpoint owner differs")
            endpoints.append({"iface": port, "owner": endpoint["ownerId"], "interface": endpoint["interfaceId"],
                              "ifindex": endpoint["ifindex"], "ofport": endpoint["ofport"],
                              "mtu": endpoint["mtu"], "bridge": endpoint["bridge"]})
            policies.append([port, {"inbound": endpoint["nftInbound"], "outbound": endpoint["nftOutbound"]}])
    covered = {port for pair in native["bridges"] for port in pair}
    if {row["iface"] for row in endpoints} != covered or len(endpoints) != len(covered):
        raise ValueError("bridge endpoint inventory is not exact")
    return sorted(endpoints, key=lambda row: row["iface"]), sorted(policies)


def build(native_path, before_path, after_path, packet_path, destination, bridge_path, intent_path):
    native, before, after, packets = [json.loads(path.read_text()) for path in
                                      [native_path, before_path, after_path, packet_path]]
    bridge = json.loads(bridge_path.read_text())
    intent = json.loads(intent_path.read_text())
    bridge_endpoints, link_policies = bridge_records(native, bridge)
    projection = project(native)
    records = {key: projection.pop(key) for key in RECORD_KEYS}
    networks, sources, attachments = source_records(native)
    roles = sizing_roles(native)
    by_interface = {row["interface"]: row for row in roles}
    for interface in records["interfaces"]:
        role = by_interface[interface["id"]]
        if role["declaredRole"] == "gray-firewall" and role["role"] != "other":
            interface["externalData"] = True
    epoch = "sizing-cohort/" + native_path.stem
    installations = key_records(native, before, after, epoch)
    services = [{"device": row["device"], "protocol": row["protocol"], "port": row["port"], "kind": "application"}
                for row in intent["services"] if row["device"] in native["deviceIds"]]
    if not services:
        raise ValueError("declared Red service inventory is empty")
    declared_pairs = {row["host"]: row for row in intent["pairs"] if row["host"] in native["deviceIds"]}
    source_flows = []
    for entry in sources:
        pair = declared_pairs[entry["sourceHost"]]
        source_flows.append({"iface": entry["iface"], "domain": entry["originDomain"],
                             "source": int(ipaddress.ip_address(pair["localAddress"])),
                             "destination": int(ipaddress.ip_address(pair["peerAddress"]))})
    result = {"records": records, "bridgeEndpoints": bridge_endpoints, "linkPolicies": link_policies,
              "services": services, "sourceFlows": source_flows, "rawBridge": bridge, "rawServiceIntent": intent, "networks": networks, "sourceEntries": sources,
              "redNetworkAttachments": attachments, "sizingRoles": roles,
              "publicInstallations": installations,
              "installations": [{key: row[key] for key in ["installation", "localIface", "materialReference"]}
                                for row in installations], "epoch": epoch,
              "rawNative": native, "rawKeysBefore": before, "rawKeysAfter": after, "rawSizing": packets,
              "projection": projection,
              "provenance": {key: {"path": str(path), "sha256": digest(path)} for key, path in
                             [("native", native_path), ("before", before_path), ("after", after_path), ("packets", packet_path), ("bridge", bridge_path), ("intent", intent_path)]}}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("native", type=Path)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("packets", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--intent", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.native, args.before, args.after, args.packets, args.destination, args.bridge, args.intent)
    print(json.dumps({"destination": str(args.destination), "networks": len(result["networks"]),
                      "sourceEntries": len(result["sourceEntries"]), "publicInstallations": len(result["publicInstallations"]),
                      "sizingInterfaces": sum(row["role"] != "other" for row in result["sizingRoles"])}))


if __name__ == "__main__":
    main()
