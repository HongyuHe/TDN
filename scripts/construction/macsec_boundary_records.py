"""Prepare finite physical-boundary records from the strict MCP export."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path


def only(values):
    if len(values) != 1:
        raise ValueError(f"expected one record, found {len(values)}")
    return values[0]


def mac(value):
    return int(value.replace(":", ""), 16)


def frame(record):
    return {key: record[key] for key in ("header", "headerBytes", "payload")}


def prepare(bundle, source_hash):
    observations = {item["id"]: item["record"] for item in bundle["observations"] if "record" in item}
    frames = {item["id"]: item for item in bundle["frames"]}
    ports = ["R:red", "A:red", "A:mac0", "A:wire", "B:wire", "B:mac0"]
    owners = ["R", "A", "B"]
    port_index = {name: index for index, name in enumerate(ports)}
    result = {"rawBundle": bundle, "sourceSha256": source_hash, "normalization": {
        "version": "physical-boundary-records-v1",
        "executionEnabled": "Model operational enabled state for an administratively UP software interface with active manually installed SA; not an observed MKA controlled-port variable.",
        "associationIndices": "Distinct local model identifiers for public installation records; no private-key or key-equality claim.",
        "ifaceNames": "Namespace-qualified interface identifiers; raw namespace, native names and ifindices remain retained.",
        "scope": "Finite routed-flow and physical-program observations, not a whole laboratory compliance claim. The first two programs intentionally admit plaintext IPv4."}}
    for case in bundle["cases"]:
        case_id = case["id"]
        interface_rows = [item for item in bundle["interfaces"] if item["case"] == case_id and item["phase"] == "before"]
        mac_rows = [item for item in bundle["macsec_ports"] if item["case"] == case_id and item["phase"] == "before"]
        policy_rows = [item for item in bundle["l2_policies"] if item["case"] == case_id and item["phase"] == "before"]
        projected_interfaces = []
        addresses = {}
        for owner in owners:
            raw = observations[case["before"][owner]["interfaces"]]
            if raw["returncode"]:
                raise ValueError("failed address observation")
            for record in json.loads(raw["stdout"]):
                addresses[owner + ":" + record["ifname"]] = [int(ipaddress.ip_address(address["local"])) for address in record["addr_info"] if address["family"] == "inet"]
        for name in ports:
            owner, native_name = name.split(":")
            row = only([item for item in interface_rows if item["device"] == owner and item["record"]["ifname"] == native_name])["record"]
            projected_interfaces.append({"id": name, "device": owner,
                "zone": "black" if native_name == "wire" else "red" if owner == "R" else "gray",
                "address": addresses[name][0] if addresses[name] else None,
                "namespaceAddresses": addresses[name],
                "linkAddress": mac(row["address"]), "physical": native_name != "mac0",
                "externalData": False, "managementNetwork": False, "mtu": row["mtu"]})
        mac_ports = []
        association_bindings = []
        for owner in ["A", "B"]:
            row = only([item for item in mac_rows if item["device"] == owner])
            if not {"UP", "LOWER_UP"}.issubset(row["flags"]):
                raise ValueError("MACsec interface is not operational")
            if row["settings"]["offload"] != "off" or row["settings"]["icv_len"] != 16:
                raise ValueError("unsupported MACsec execution shape")
            after = only([item for item in bundle["macsec_ports"] if item["case"] == case_id and item["phase"] == "after" and item["device"] == owner])
            if row["settings"] != after["settings"]:
                raise ValueError("changed MACsec settings")
            associations = {}
            for direction in ["tx", "rx"]:
                association = only([item for item in row["associationRecords"] if item["direction"] == direction and item["active"]])
                generation = 11 + 10 * (owner == "B") + (direction == "rx")
                associations[direction] = {"tag": 1, "sci": association["sci"], "associationNumber": association["an"], "keyGeneration": generation}
                association_bindings.append({"device": owner, "direction": direction, "publicInstallation": association, "model": associations[direction], "observation": row["associationObservation"]})
            physical_name = owner + ":" + row["physicalName"]
            logical_name = owner + ":" + row["logicalName"]
            physical = only([item["record"] for item in interface_rows if item["device"] == owner and item["record"]["ifname"] == row["physicalName"]])
            if physical["ifindex"] != row["physicalIndex"]:
                raise ValueError("physical parent mismatch")
            mac_ports.append({"logicalIface": port_index[logical_name], "physicalIface": port_index[physical_name],
                "settings": {"controlledPortEnabled": True, "protectFrames": row["settings"]["protect"], "encryptFrames": row["settings"]["encrypt"], "confidentialityOffset": 0},
                "transmitAssociation": associations["tx"], "receiveAssociations": [associations["rx"]], "validateStrict": row["settings"]["validation"] == "strict"})
        policies = []
        for owner in ["A", "B"]:
            selected = {direction: only([item for item in policy_rows if item["device"] == owner and item["direction"] == direction]) for direction in ["ingress", "egress"]}
            if any(item["interface"] != "wire" for item in selected.values()):
                raise ValueError("wrong physical program binding")
            policies.append([port_index[owner + ":wire"], {"inbound": selected["ingress"]["program"], "outbound": selected["egress"]["program"]}])
        for pair in case["physicalFramePairs"]:
            send, receive = frames[pair["send"]], frames[pair["receive"]]
            if send["bytes"] != receive["bytes"] or hashlib.sha256(bytes.fromhex(send["bytes"])).hexdigest() != pair["sha256"]:
                raise ValueError("physical frame identity mismatch")
        source = frames[case["sourceArrivalFrames"][0]]
        logical = frames[case["logicalTransmitFrames"][0]]
        physical = frames[case["physicalFramePairs"][0]["send"]] if case["physicalFramePairs"] else logical
        if case_id != "unprotected-denied" and physical["interface"] != "wire":
            raise ValueError("missing physical transmission")
        if logical["ipv4"]["ttl"] + 1 != source["ipv4"]["ttl"]:
            raise ValueError("routed TTL mismatch")
        raw_network = source["payload"]
        ihl = raw_network[0] % 16 * 4
        application = list(bytes.fromhex(source["ipv4"]["payloadHex"]))
        if raw_network[ihl + 8:] != application or not application:
            raise ValueError("missing application payload")
        header = {"source": source["ipv4"]["source"], "destination": source["ipv4"]["destination"], "protocol": "udp", "ingress": "", "egress": "", "sourcePort": source["ipv4"]["sourcePort"], "destinationPort": source["ipv4"]["destinationPort"], "ipv4HeaderWords": ihl // 4, "matchedInboundPolicyIds": [], "matchedOutboundPolicyIds": [], "connectionState": "new", "hopLimit": source["ipv4"]["ttl"], "payloadBytes": application, "networkBytes": len(raw_network), "ipv4FragmentOffset": 0, "ipv6NextHeader": 0, "icmpType": 0, "icmpCode": 0, "etherType": None, "connectionId": None}
        raw_routes = json.loads(observations[case["before"]["A"]["routes"]]["stdout"])
        route_record = only([item for item in raw_routes if item.get("dev") == "mac0" and "table" not in item])
        network = ipaddress.ip_network(route_record["dst"])
        route = {"ingress": port_index["A:red"], "egress": port_index["A:mac0"], "low": int(network.network_address), "high": int(network.broadcast_address), "prefixLength": network.prefixlen, "metric": route_record.get("metric", 0), "tablePriority": 32766}
        native_devices = [{"forwardRules": [], "inputRules": [], "outputRules": [], "forwardFallback": "allow", "inputFallback": "allow", "outputFallback": "allow", "outbound": [], "inbound": [], "states": [], "localAddresses": [address for name in ports if name.startswith(owner + ":") for address in addresses[name]], "ifaceSecurityDomain": None} for owner in owners]
        profile = {"interfaces": projected_interfaces, "sender": projected_interfaces[3], "receiver": projected_interfaces[4], "ownerNames": owners,
            "nativeDevices": native_devices,
            "nativeIfaces": [{"owner": owners.index(name.split(":")[0]), "name": name, "stack": [], "canOriginateTraffic": name == "R:red"} for name in ports],
            "routes": [route], "links": [[port_index[a], port_index[b]] for a, b in bundle["physicalLinks"] for a, b in [(a, b), (b, a)]],
            "macIfaces": mac_ports, "linkPolicies": policies,
            "sourceCase": {"entryIface": port_index["A:red"], "route": route, "header": header, "application": application, "originDomain": 1, "mac": mac_ports[0], "peerIface": port_index["B:wire"]},
            "sourceFrame": frame(source), "logicalFrame": frame(logical), "physicalFrame": frame(physical),
            "sourceNetwork": source["payload"][:ihl], "sourceTransport": source["payload"][ihl:ihl+8],
            "logicalNetwork": logical["payload"][:ihl], "logicalTransport": logical["payload"][ihl:ihl+8],
            "associationBindings": association_bindings, "case": case,
            "physicalFrameOrigin": "observed physical frame" if case["physicalFramePairs"] else "attempted protect-off frame, derived from observed logical bytes; no physical wire emission claimed"}
        result[{"protected": "protected", "unprotected-allowed": "unprotectedAllowed", "unprotected-denied": "unprotectedDenied"}[case_id]] = {key: profile[key] for key in ["interfaces", "sender", "receiver", "ownerNames", "nativeDevices", "nativeIfaces", "routes", "links", "macIfaces", "linkPolicies", "sourceCase", "sourceFrame", "logicalFrame", "physicalFrame", "sourceNetwork", "sourceTransport", "logicalNetwork", "logicalTransport"]}
        result[case_id + "Provenance"] = {key: profile[key] for key in ["associationBindings", "case", "physicalFrameOrigin"]}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    raw = args.source.read_bytes()
    args.destination.write_text(json.dumps(prepare(json.loads(raw), hashlib.sha256(raw).hexdigest()), indent=2) + "\n")


if __name__ == "__main__":
    main()
