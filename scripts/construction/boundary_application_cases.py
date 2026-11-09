"""Build actual local-hook cases for declared Red services and firewall boundaries."""
import copy
import json
from pathlib import Path
import struct

from boundary_transform_cases import case, checksum, route


def firewall_case(records, owner, entry_name, source, destination, direction):
    entry = records["ifaceNames"].index(owner + ":" + entry_name)
    selected = route(records, entry, destination)
    exit_port = selected["egress"]
    payload = [1, 2, 3, 4, 0, 0, 0, 1]
    header = {"source": source, "destination": destination, "protocol": "esp",
              "ingress": "", "egress": "", "sourcePort": 0, "destinationPort": 0,
              "ipv4HeaderWords": 5, "matchedInboundPolicyIds": [], "matchedOutboundPolicyIds": [],
              "connectionState": "new", "hopLimit": 64, "payloadBytes": None,
              "networkBytes": 28, "ipv4FragmentOffset": None, "ipv6NextHeader": 0,
              "icmpType": 0, "icmpCode": 0, "etherType": None, "connectionId": None}
    network = struct.pack("!BBHHHBBHII", 69, 0, 28, 0, 0, 63, 50, 0, source, destination)
    network = network[:10] + struct.pack("!H", checksum(network)) + network[12:]
    observed_port = entry if direction == "inbound" else exit_port
    return {"interface": records["interfaces"][observed_port], "entryIface": entry,
            "route": selected, "header": header, "network": list(network), "transport": [],
            "payload": payload, "entryMtu": records["interfaces"][entry]["mtu"],
            "exitMtu": records["interfaces"][exit_port]["mtu"], "bytes": 28}


def main():
    for profile, prefix, level in [("Baseline", "V31B", 1), ("Shared", "V31F", 2)]:
        data = json.loads(Path("data/evidence/continuation/Boundary" + profile + ".json").read_text())
        records = json.loads(Path("data/evidence/continuation/Boundary" + profile + "Fields.json").read_text())
        red = case(records, prefix, "inner", level)["forward"]
        red["interface"] = records["interfaces"][red["entryIface"]]
        wrong = case(records, prefix, "inner", level, 8081)["forward"]
        wrong["interface"] = records["interfaces"][wrong["entryIface"]]
        firewall = prefix + "_OF_A1"
        local_outer = next(item["outer"] for item in data["firewalls"] if item["firewall"] == firewall)
        peer = next(item for item in data["peers"] if item["source"] == local_outer)
        source, destination = peer["sourceAddress"], peer["destinationAddress"]
        outbound = firewall_case(records, firewall, "inside", source, destination, "inbound")
        wire = firewall_case(records, firewall, "inside", source, destination, "outbound")
        inbound = firewall_case(records, firewall, "outside", destination, source, "inbound")
        wrong_source = next(item["address"] for item in records["interfaces"]
                            if item["id"] == firewall + ":inside")
        rejected = firewall_case(records, firewall, "inside", wrong_source, destination, "inbound")
        output = {"redHTTP": red, "redWrongPort": wrong, "firewallInside": outbound,
                  "firewallOutsideOutput": wire, "firewallOutsideInput": inbound,
                  "firewallWrongSource": rejected}
        Path("data/evidence/continuation/BoundaryApplication" + profile + ".json").write_text(
            json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
