"""Bind public MKA messages to daemon events and packet observations."""
import hashlib
import json
from pathlib import Path

from . import eap, eap_public
from .parsers.snapshot import require


CAPABILITIES = eap_public.CAPABILITIES + ["mka_messages", "causal_links"]
LEAN_VIEW = "authentication_causal_history"
SCOPE = "Public EAP-TLS exchange, exact MKA messages, and observed event dependencies"


def location(event):
    return {key: event[key] for key in ["device", "observation", "line"]}


def frame(encoded):
    raw = bytes.fromhex(encoded)
    require(len(raw) >= 22 and raw[12:14] == b"\x88\x8e" and raw[14] >= 3 and raw[15] == 5,
            "Expected a complete MKA Ethernet frame")
    require(int.from_bytes(raw[16:18], "big") + 18 == len(raw), "MKA frame length mismatch")
    return {"hex": encoded, "bytes": len(raw), "sourceAddress": raw[6:12].hex(),
            "destinationAddress": raw[:6].hex(), "sha256": hashlib.sha256(raw).hexdigest()}


def causal_mka(directory, report):
    peers = report["authentication"][0]["peers"]
    peer_ids = {peer["device"] for peer in peers}
    addresses = {row["device"]: row["interface"]["address"].replace(":", "")
        for row in report["interfaces"] if row["device"] in peer_ids and
        row["interface"].get("ifname") == "eth0"}
    require(set(addresses) == peer_ids and len(set(addresses.values())) == 2,
            "Missing or duplicate MKA peer addresses")
    logs = {device: sorted([event for event in report["events"] if event["device"] == device],
                          key=lambda event: event["line"]) for device in sorted(peer_ids)}
    wire = []
    for command in json.loads((Path(directory) / "commands.json").read_text()):
        argv = command["command"]
        if len(argv) != 2 or argv[0] != "cat" or Path(argv[1]).name not in {"P0-headers.log", "P1-headers.log"}:
            continue
        device = Path(argv[1]).name.split("-")[0]
        for line, text in enumerate(command["stdout"].splitlines(), 1):
            row = json.loads(text)
            if row.get("mka_hex") is None:
                continue
            packet = frame(row["mka_hex"])
            require(packet["sourceAddress"] == row["source"] and packet["destinationAddress"] == row["destination"] and
                    packet["bytes"] == row["length"] and row["ethertype"] == "888e" and row["eapol_type"] == 5,
                    "Captured MKA bytes disagree with packet metadata")
            wire.append(packet | {"device": device, "observation": command["id"], "line": line,
                                  "packetType": row["pkttype"]})
    require(bool(wire), "No public MKA packet capture")
    messages, links, sends = [], [], {}
    for device, events in logs.items():
        require(len({event["observation"] for event in events}) == 1, "Multiple process logs need explicit process identity")
        for left, right in zip(events, events[1:]):
            links.append({"kind": "same_process_order", "before": location(left), "after": location(right)})
        for index, event in enumerate(events):
            if event.get("recordType") != "MKA_SEND":
                continue
            packet = frame(event["hex"])
            require(packet["sourceAddress"] == addresses[device], "MKA sender address differs from its interface")
            require(index + 1 < len(events) and events[index + 1]["kind"] == "mka_send_result" and
                    events[index + 1]["result"] >= 0, "MKA send did not succeed")
            result = events[index + 1]
            require(result["result"] in {0, packet["bytes"]}, "Partial MKA send")
            require(event["hex"] not in sends, "Repeated identical MKA sends need explicit occurrence matching")
            observed = [item for item in wire if item["device"] == device and
                        item["hex"] == event["hex"] and item["packetType"] == 4]
            require(bool(observed), "MKA send has no matching outgoing frame")
            record = packet | {"device": device, "send": location(event), "sendResult": location(result),
                "sendReturnValue": result["result"], "outgoingObservations": [location(item) for item in observed],
                "receives": [], "authenticatedReceives": []}
            sends[event["hex"]] = record
            messages.append(record)
    for device, events in logs.items():
        latest_receive = None
        for index, event in enumerate(events):
            kind = event.get("recordType")
            if kind == "MKA_RECEIVE":
                packet = frame(event["hex"])
                require(event["hex"] in sends and sends[event["hex"]]["device"] != device,
                        "MKA receipt has no matching peer send")
                observed = [item for item in wire if item["device"] == device and
                            item["hex"] == event["hex"] and item["packetType"] != 4]
                require(bool(observed), "MKA receipt has no incoming packet observation")
                sends[event["hex"]]["receives"].append({"event": location(event),
                    "incomingObservations": [location(item) for item in observed]})
                links.append({"kind": "matching_message", "before": sends[event["hex"]]["send"],
                              "after": location(event), "messageSha256": packet["sha256"]})
                latest_receive = event
            elif kind == "MKA_AUTHENTICATED":
                require(latest_receive is not None and latest_receive["hex"] == event["hex"],
                        "MKA integrity result has no matching received frame")
                require(index + 1 < len(events) and events[index + 1]["kind"] == "authenticated_mka_peer" and
                        events[index + 1]["peerAddress"] == frame(event["hex"])["sourceAddress"],
                        "MKA integrity result differs from peer authentication")
                sends[event["hex"]]["authenticatedReceives"].append({"event": location(event),
                    "authentication": location(events[index + 1])})
    require(all(any(item["event"]["device"] == device for message in messages
                    for item in message["authenticatedReceives"]) for device in peer_ids),
            "Both peers need message-bound MKA authentication")
    vertices = {(event["device"], event["observation"], event["line"]) for events in logs.values() for event in events}
    edges = {vertex: set() for vertex in vertices}
    indegree = dict.fromkeys(vertices, 0)
    for link in links:
        left, right = (tuple(link[side][key] for key in ["device", "observation", "line"])
                       for side in ["before", "after"])
        if right not in edges[left]:
            edges[left].add(right)
            indegree[right] += 1
    ready = [vertex for vertex in vertices if indegree[vertex] == 0]
    visited = 0
    while ready:
        vertex = ready.pop()
        visited += 1
        for successor in edges[vertex]:
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)
    require(visited == len(vertices), "Observed MKA event dependencies form a cycle")
    return messages, links


def parse(directory):
    manifest, report = eap_public.parse(directory)
    report["mka_messages"], report["causal_links"] = causal_mka(directory, report)
    report["projectionVersion"] = "eap-mka-public-v1"
    report["scope"].append("Causal links come from same-process event order and matching public MKA messages. No physical total order across processes is inferred. Hostap's successful integrity checks remain implementation observations.")
    return manifest, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return eap.query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    parse(directory)
    return eap.read_experiment_raw(directory, observation, stderr)


def export_experiment(directory, destination):
    _, report = parse(directory)
    return eap.export_report(report, destination, LEAN_VIEW)
