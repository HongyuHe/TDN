import argparse
import hashlib
import json
from pathlib import Path


def only(values, meaning):
    values = list(values)
    if len(values) != 1:
        raise ValueError((meaning, len(values)))
    return values[0]


def build(path):
    data = json.loads(path.read_text())
    records = data["records"]
    plans = []
    for context in records["contexts"]:
        entry = only((entry for entry in records["entries"] if entry["originDomain"] == context["originDomain"]), "source")
        destination = only((entry for entry in records["entries"] if entry["network"] == context["flow"]["destinationNetwork"]), "destination")
        flow = only((flow for flow in records["sourceFlows"] if flow["domain"] == context["originDomain"]), "source flow")
        source_sa = only((index for index, record in enumerate(records["installations"]) if record["installation"]["direction"] == "outbound" and record["installation"]["device"] == context["sourceInnerOwner"] and record["installation"]["association"]["spi"] == context["innerStamp"]["association"]), "source SA")
        destination_sa = only((index for index, record in enumerate(records["installations"]) if record["installation"]["direction"] == "inbound" and record["installation"]["device"] == context["destinationInnerOwner"] and record["installation"]["association"]["spi"] == context["innerStamp"]["association"]), "receive SA")
        source_mac = only((index for index, mac in enumerate(records["macIfaces"]) if mac["transmitAssociation"] == context["outerAssociation"]), "source MACsec iface")
        destination_mac = only((index for index, mac in enumerate(records["macIfaces"]) if mac["logicalIface"] == context["destinationLogicalIface"]), "receive MACsec iface")
        receive_mac = only((index for index, association in enumerate(records["macIfaces"][destination_mac]["receiveAssociations"]) if association["sci"] == context["outerAssociation"]["sci"] and association["associationNumber"] == context["outerAssociation"]["associationNumber"]), "receive MACsec association")
        moves = []
        def move(operation, **kwargs):
            moves.append(dict({"operation": operation, "index": 0, "saIndex": 0, "macIndex": 0, "rxIndex": 0, "domain": 0, "sourceIndex": 0}, **kwargs))
        def next_iface(iface):
            return only((last for first, last in records["links"] if first == iface), "physical neighbour")
        def route(ingress, address):
            choices = [(index, route) for index, route in enumerate(records["routes"]) if route["ingress"] == ingress and route["destPrefixLow"] <= address <= route["destPrefixHigh"]]
            index, selected = min(choices, key=lambda item: (item[1]["tablePriority"], -item[1]["prefixLength"], item[1]["metric"], item[0]))
            move("route", index=index)
            return selected["egress"]
        move("receive")
        source_inner_gray = route(entry["iface"], flow["destination"])
        move("forwardFilter")
        move("encryptIPsec", saIndex=source_sa)
        source_inner_gray = route(source_inner_gray, context["innerStamp"]["receiver"])
        source_outer_gray = next_iface(source_inner_gray)
        move("linkTransmit", index=source_outer_gray)
        move("receive")
        source_logical = route(source_outer_gray, context["innerStamp"]["receiver"])
        if source_logical != records["macIfaces"][source_mac]["logicalIface"]:
            raise ValueError("MACsec routing mismatch")
        move("forwardFilter")
        move("forwardWithoutEncap")
        move("encryptMACsec", macIndex=source_mac)
        bridge_source = next_iface(records["macIfaces"][source_mac]["physicalIface"])
        move("linkTransmit", index=bridge_source)
        destination_physical = records["macIfaces"][destination_mac]["physicalIface"]
        bridge_destination = only((first for first, last in records["links"] if last == destination_physical), "remote bridge attachment")
        if [bridge_source, bridge_destination] not in records["bridges"]:
            raise ValueError("Missing bridge edge")
        move("bridge", index=bridge_destination)
        move("linkTransmit", index=destination_physical)
        move("decryptMACsec", macIndex=destination_mac, rxIndex=receive_mac)
        move("receive")
        destination_outer_gray = route(context["destinationLogicalIface"], context["innerStamp"]["receiver"])
        move("forwardFilter")
        move("forwardWithoutEncap")
        destination_inner_gray = next_iface(destination_outer_gray)
        move("linkTransmit", index=destination_inner_gray)
        move("decryptIPsec", saIndex=destination_sa, sourceIndex=source_sa)
        destination_inner_red = route(destination_inner_gray, flow["destination"])
        move("forwardFilter")
        move("forwardWithoutEncap")
        destination_host = next_iface(destination_inner_red)
        if destination_host != destination["hostIface"]:
            raise ValueError("Recipient iface mismatch")
        move("linkTransmit", index=destination_host)
        move("receive")
        move("inputFilter")
        move("deliver", domain=destination["originDomain"])
        plans.append({"sourceFlow": flow, "moves": moves, "destinationIface": destination_host, "destinationDomain": destination["originDomain"], "destinationNetwork": destination["network"]})
    return {"plans": plans, "provenance": {"input": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "meaning": "Constructed successful model paths selected from imported routes, physical links, bridge edges, SAs and directional SCI bindings; no claim that these model steps are a recovered packet capture."}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("data/evidence/nestedProtection/MixedIPsecMACsec.json"))
    parser.add_argument("--output", type=Path, default=Path("data/evidence/nestedProtection/MixedDeliveryPlans.json"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build(args.input), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
