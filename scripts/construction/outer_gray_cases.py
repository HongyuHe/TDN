"""Build concrete framed packet records and retain the raw address projection inputs."""
import ipaddress
import json
from pathlib import Path
import struct


def packet_header(source, destination, source_port, destination_port, payload):
    return {"source": source, "destination": destination, "protocol": "udp", "ingress": "", "egress": "",
            "sourcePort": source_port, "destinationPort": destination_port, "ipv4HeaderWords": 5,
            "inboundPolicies": [], "outboundPolicies": [], "connectionState": "new", "ipv6NextHeader": 0,
            "icmpType": 0, "icmpCode": 0, "hopLimit": 64, "etherType": None, "payloadBytes": payload,
            "connectionId": None, "networkBytes": 28 + len(payload), "ipv4FragmentOffset": 0}


def make_case(records, gray_name, pair_index, source_port, destination_port):
    pair = records["pairs"][pair_index]["endpoints"]
    port = records["ifaceNames"].index(gray_name)
    destination = pair["destinationAddress"]
    routes = [route for route in records["routes"] if route["ingress"] == port and route["low"] <= destination <= route["high"]]
    route = min(routes, key=lambda item: (item["tablePriority"], -item["prefixLength"], item["metric"]))
    payload = [0] * 17 + [32] + [0] * 9 + [28]
    header = packet_header(pair["sourceAddress"], destination, source_port, destination_port, payload)
    transport = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    network = struct.pack("!BBHHHBBHII", 69, 0, 28 + len(payload), 0, 0, 63, 17, 0, pair["sourceAddress"], destination)
    checksum = sum(struct.unpack("!10H", network))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    network = network[:10] + struct.pack("!H", (~checksum) & 65535) + network[12:]
    return {"interface": records["interfaces"][port], "entryIface": port, "route": route, "header": header,
            "network": list(network), "transport": list(transport), "payload": payload,
            "entryMtu": records["interfaces"][port]["mtu"], "exitMtu": records["interfaces"][route["egress"]]["mtu"],
            "bytes": 28 + len(payload)}



def make_plain_black_case(records, prefix, level):
    pair_index = next(index for index, pair in enumerate(records["pairs"])
                      if pair["endpoints"]["source"] == prefix + "_I_B" + str(level) and
                      pair["endpoints"]["destination"] == prefix + "_I_A" + str(level))
    case = make_case(records, prefix + "_O_A1:black", pair_index, 0, 0)
    payload = [1, 2, 3, 4, 0, 0, 0, 1]
    header = {**case["header"], "protocol": "esp", "sourcePort": 0, "destinationPort": 0,
              "payloadBytes": None, "networkBytes": 28, "ipv4FragmentOffset": None}
    network = struct.pack("!BBHHHBBHII", 69, 0, 28, 0, 0, 63, 50, 0, header["source"], header["destination"])
    checksum = sum(struct.unpack("!10H", network))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    network = network[:10] + struct.pack("!H", (~checksum) & 65535) + network[12:]
    return {**case, "interface": records["interfaces"][case["route"]["egress"]],
            "header": header, "network": list(network), "transport": [], "payload": payload, "bytes": 28}


def main():
    for profile, prefix, gray, pair_index in (("Baseline", "V31B", "gray", 0), ("Shared", "V31F", "gray2", 1)):
        path = Path("data/evidence/continuation") / ("OuterGray" + profile + ".json")
        saved = json.loads(path.read_text())
        records, bundle = saved["records"], saved["rawBundle"]
        raw_interfaces = {item["id"]: item for item in bundle["sourceInterfaces"]}
        all_addresses = []
        for interface in records["interfaces"]:
            source = raw_interfaces[interface["id"]]
            addresses = [item for item in source["addresses"] if item["family"] == "inet"]
            if len(addresses) > 1:
                raise ValueError("raw IPv4 interface expansion is required")
            all_addresses.append({**interface, "address": int(ipaddress.ip_address(addresses[0]["local"])) if addresses else None})
        result = {"reply": make_case(records, prefix + "_O_A1:" + gray, pair_index, 500, 9999),
                  "serviceCollision": make_case(records, prefix + "_O_A1:" + gray, pair_index, 1812, 500),
                  "rawInterfaces": all_addresses,
                  "plaintextBlack": make_plain_black_case(records, prefix, pair_index + 1)}
        owner = bundle["deviceIds"][prefix + "_O_A1"]
        policy = next(item for item in records["nativeDevices"][owner]["inbound"]
                      if item["sourceLow"] <= result["plaintextBlack"]["header"]["source"] <= item["sourceHigh"] and
                      item["destinationLow"] <= result["plaintextBlack"]["header"]["destination"] <= item["destinationHigh"])
        association = next(item for item in records["nativeDevices"][owner]["states"]
                           if item["localRequestId"] == policy["id"] and item["sender"] == policy["sender"] and
                           item["receiver"] == policy["receiver"])
        outer = {item["id"] for item in records["components"] if item["layer"] == "outer"}
        result["outerGrayInterfaces"] = [item for item in records["interfaces"] if item["device"] in outer and item["zone"] == "gray"]
        result.update({"inboundPolicy": policy, "inboundAssociation": association,
                       "loopbackIface": records["ifaceNames"].index(prefix + "_O_A1:lo"),
                       "erspanIface": records["ifaceNames"].index(prefix + "_O_A1:erspan0")})
        path.with_stem(path.stem + "Cases").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
