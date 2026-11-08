"""Bind observed full frames and useful modeled paths to the aligned sizing records."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path


def selected_route(records, ingress, destination):
    candidates = [row for row in records["routes"] if row["ingress"] == ingress and row["low"] <= destination <= row["high"]]
    if not candidates:
        raise ValueError("modeled path lacks a route")
    return min(candidates, key=lambda row: (row["tablePriority"], -row["prefixLength"], row["metric"]))


def build(source, destination):
    saved = json.loads(source.read_text())
    records = saved["records"]
    flow = saved["sourceFlows"][0]
    route = selected_route(records, flow["iface"], flow["destination"])
    owner = records["nativeIfaces"][route["egress"]]["owner"]
    policies = [row for row in records["nativeDevices"][owner]["outbound"]
                if row["sourceLow"] <= flow["source"] <= row["sourceHigh"] and
                row["destinationLow"] <= flow["destination"] <= row["destinationHigh"]]
    policy = min(policies, key=lambda row: row["priority"])
    sas = [row for row in saved["installations"] if row["installation"]["device"] == owner and
           row["installation"]["direction"] == "outbound" and
           row["installation"]["association"]["localRequestId"] == policy["id"] and
           row["installation"]["association"]["sender"] == policy["sender"] and
           row["installation"]["association"]["receiver"] == policy["receiver"]]
    if len(sas) != 1:
        raise ValueError("modeled path lacks one installed outbound SA")
    outer_route = selected_route(records, route["egress"], policy["receiver"])
    links = [row[1] for row in records["links"] if row[0] == outer_route["egress"]]
    if len(links) != 1:
        raise ValueError("modeled path lacks one physical next port")
    path = {"flow": flow, "route": route, "policy": policy, "association": sas[0]["installation"]["association"],
            "routeOuterPacket": outer_route, "nextIface": links[0]}
    packets = []
    for packet in saved["rawSizing"]["packets"]:
        frame = bytes.fromhex(packet["frame_hex"])
        if len(frame) != packet["frame_bytes"] or int.from_bytes(frame[12:14], "big") != 2048:
            raise ValueError("unsupported or inconsistent captured Ethernet frame")
        ip = frame[14:]
        fields = {"source": int.from_bytes(ip[12:16], "big"), "destination": int.from_bytes(ip[16:20], "big"),
                  "protocol": ip[9], "networkBytes": int.from_bytes(ip[2:4], "big"),
                  "headerBytes": (ip[0] % 16) * 4, "fragmentOffset": (int.from_bytes(ip[6:8], "big") % 8192) * 8,
                  "moreFragments": bool(int.from_bytes(ip[6:8], "big") // 8192 % 2),
                  "dontFragment": bool(int.from_bytes(ip[6:8], "big") // 16384 % 2)}
        expected = {"source": int(ipaddress.ip_address(packet["source"])),
                    "destination": int(ipaddress.ip_address(packet["destination"])),
                    "protocol": packet["protocol"], "networkBytes": packet["ip_bytes"], "headerBytes": packet["ip_header_bytes"],
                    "fragmentOffset": packet["fragment_offset"], "moreFragments": packet["mf"], "dontFragment": packet["df"]}
        if fields != expected or len(ip) != fields["networkBytes"]:
            raise ValueError("raw frame and parsed IP fields differ")
        name = packet["device"] + ":" + packet["interface"]
        port = records["ifaceNames"].index(name)
        outbound = inbound = None
        if fields["protocol"] == 50:
            if fields["fragmentOffset"] or fields["moreFragments"]:
                raise ValueError("captured ESP fragment needs additional reassembly binding")
            spi = int.from_bytes(ip[fields["headerBytes"]:fields["headerBytes"]+4], "big")
            matches = [(index, row) for index, row in enumerate(saved["installations"])
                       if row["installation"]["association"]["wireIdentity"] == spi and
                       row["installation"]["association"]["sender"] == fields["source"] and
                       row["installation"]["association"]["receiver"] == fields["destination"]]
            outs = [index for index, row in matches if row["installation"]["direction"] == "outbound"]
            ins = [index for index, row in matches if row["installation"]["direction"] == "inbound"]
            if len(outs) != 1 or len(ins) != 1:
                raise ValueError("captured ESP lacks one aligned sender/receiver SA pair")
            outbound, inbound = outs[0], ins[0]
        packets.append({"id": packet["id"], "iface": port, "interface": name, "bytes": list(frame), **fields,
                        "outboundIndex": outbound, "inboundIndex": inbound})
    result = {"path": path, "frames": packets, "cases": saved["rawSizing"]["cases"],
              "source": str(source), "sourceSHA256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "scope": "Observed frame header/length/MTU and public-SA epoch alignment. No ciphertext replay or guaranteed OVS delivery claim."}
    destination.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    result = build(args.source, args.destination)
    print(json.dumps({"frames": len(result["frames"]), "cases": len(result["cases"]), "path": result["path"]["flow"]}))


if __name__ == "__main__":
    main()
