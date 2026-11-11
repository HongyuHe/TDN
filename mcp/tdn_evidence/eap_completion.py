"""Connect EAP completion, backend delivery, and MKA by recorded messages."""
from collections import deque
import hashlib
import json
from pathlib import Path

from . import eap, eap_mka, eap_public
from .parsers.snapshot import require

CAPABILITIES = eap_mka.CAPABILITIES + ["completion_messages", "completion_bindings"]
LEAN_VIEW = "authentication_complete_history"
SCOPE = "Message-bound EAP completion and MKA history for one captured exchange"


def identity(event):
    return tuple(event[key] for key in ["device", "observation", "line"])


def single(events, predicate, description):
    return eap_public.one([event for event in events if predicate(event)], description)


def public(events, kind):
    return single(events, lambda event: event.get("recordType") == kind,
                  "Expected one public " + kind)


def causal_path(events, links, start, finish):
    by_id = {identity(event): event for event in events}
    require(len(by_id) == len(events), "Duplicate event identity")
    edges = {key: set() for key in by_id}
    indegree = dict.fromkeys(by_id, 0)
    for link in links:
        left, right = identity(link["before"]), identity(link["after"])
        require(left in edges and right in edges and left != right, "Invalid causal-link endpoint")
        if right not in edges[left]:
            edges[left].add(right)
            indegree[right] += 1
    ready = deque(key for key, degree in indegree.items() if degree == 0)
    visited = 0
    while ready:
        key = ready.popleft()
        visited += 1
        for child in edges[key]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    require(visited == len(edges), "Observed authentication dependencies form a cycle")
    first, last = identity(start), identity(finish)
    require(first in edges and last in edges and first != last, "Invalid causal-path endpoint")
    pending = deque([(first, [first])])
    seen = {first}
    while pending:
        current, path = pending.popleft()
        for successor in sorted(edges[current]):
            if successor == last:
                return [eap_mka.location(by_id[key]) for key in path + [last]]
            if successor not in seen:
                seen.add(successor)
                pending.append((successor, path + [successor]))
    raise ValueError("No message/process-order path connects authentication to key derivation")


def completion(directory, report):
    exchange = report["exchanges"][0]
    auth, supp = exchange["authenticator"], exchange["supplicant"]
    logs = {device: sorted([event for event in report["events"] if event["device"] == device],
                          key=lambda event: event["line"]) for device in ["AS", auth, supp]}
    require(all(len({event["observation"] for event in events}) == 1 for events in logs.values()),
            "Each participant needs one identified process log")
    links = list(report["causal_links"])
    for left, right in zip(logs["AS"], logs["AS"][1:]):
        links.append({"kind": "same_process_order", "before": eap_mka.location(left),
                      "after": eap_mka.location(right)})
    radius_send = public(logs["AS"], "RADIUS_RESPONSE_SEND")
    radius_receive = public(logs[auth], "RADIUS_RESPONSE")
    radius_accept = single(logs[auth], lambda event: event["kind"] == "verified_radius_accept",
                           "Expected one verified RADIUS receipt")
    require(radius_send["hex"] == radius_receive["hex"] == exchange["protectedRecordHex"],
            "AS response bytes differ from the verified backend response")
    response = eap_public.radius(bytes.fromhex(radius_send["hex"]), 2)
    eap_send = public(logs[auth], "EAP_SUCCESS_SEND")
    eap_receive = public(logs[supp], "EAP_SUCCESS_RECEIVE")
    require(eap_send["hex"] == eap_receive["hex"], "EAP-Success send and receive bytes differ")
    success = bytes.fromhex(eap_send["hex"])
    require(len(success) == 8 and success[1:3] == b"\x00\x00" and success[3] == 4 and
            success[4] == 3 and success[6:8] == b"\x00\x04", "Malformed EAP-Success EAPOL message")
    require(eap_public.attribute(response, 79) == success[4:],
            "Forwarded EAP-Success differs from the authenticated RADIUS EAP message")
    require(radius_accept["line"] < radius_receive["line"] < eap_send["line"],
            "EAP-Success was sent before verified backend delivery")
    messages = []
    for kind, sender, receiver, accepted, device in [
        ("RADIUS_RESPONSE", radius_send, radius_receive, radius_accept, "AS"),
        ("EAP_SUCCESS", eap_send, eap_receive, eap_receive, auth),
    ]:
        events = logs[device]
        index = events.index(sender)
        require(index + 1 < len(events), "Missing completion send result")
        result = events[index + 1]
        require(result["kind"] == "completion_send_result" and result["messageType"] == kind and
                result["bytes"] == sender["bytes"] and result["result"] in
                ({sender["bytes"]} if kind == "RADIUS_RESPONSE" else {sender["bytes"] + 14}),
                "Failed or partial completion-message send")
        digest = hashlib.sha256(bytes.fromhex(sender["hex"])).hexdigest()
        links.append({"kind": "matching_message", "before": eap_mka.location(sender),
                      "after": eap_mka.location(accepted), "messageSha256": digest})
        messages.append({"messageType": kind, "hex": sender["hex"], "sha256": digest,
                         "send": eap_mka.location(sender), "sendResult": eap_mka.location(result),
                         "receive": eap_mka.location(receiver), "accepted": eap_mka.location(accepted)})
    captured = []
    auth_iface = single(report["interfaces"], lambda row: row["device"] == auth and
                        row["interface"].get("ifname") == "eth0", "Missing authenticator Ethernet interface")
    auth_address = auth_iface["interface"]["address"].replace(":", "")
    for command in json.loads((Path(directory) / "commands.json").read_text()):
        argv = command["command"]
        if len(argv) != 2 or argv[0] != "cat" or Path(argv[1]).name not in {"P0-headers.log", "P1-headers.log"}:
            continue
        device = Path(argv[1]).name.split("-")[0]
        for number, line in enumerate(command["stdout"].splitlines(), 1):
            row = json.loads(line)
            if row.get("eap_success_hex") == eap_send["hex"]:
                require(row["ethertype"] == "888e" and row["eapol_type"] == 0 and row["length"] == 22 and
                        row["source"] == auth_address and row["destination"] == "0180c2000003",
                        "EAP-Success capture metadata differs from bytes")
                captured.append({"device": device, "observation": command["id"], "line": number,
                                 "packetType": row["pkttype"]})
    require(any(row["device"] == auth and row["packetType"] == 4 for row in captured) and
            any(row["device"] == supp and row["packetType"] != 4 for row in captured),
            "Missing outgoing or incoming EAP-Success capture")
    messages[1]["wireObservations"] = captured
    completed = public(logs["AS"], "EAP_SESSION")
    verified = single(logs["AS"], lambda event: event["kind"] == "verified_certificate",
                      "Expected one AS peer-certificate verification")
    bindings = []
    for device in [auth, supp]:
        derived = eap.unique_reference(logs[device], "Derived CAK", 32)
        bindings.append({"device": device, "asCertificateVerification": eap_mka.location(verified),
                         "asCompletedSession": eap_mka.location(completed),
                         "cakDerivation": eap_mka.location(derived),
                         "sessionHex": exchange["sessionHex"],
                         "certificateToSessionPath": causal_path(report["events"], links, verified, completed),
                         "sessionToCakPath": causal_path(report["events"], links, completed, derived)})
    return messages, links, bindings


def parse(directory):
    manifest, report = eap_mka.parse(directory)
    report["completion_messages"], report["causal_links"], report["completion_bindings"] = completion(directory, report)
    report["projectionVersion"] = "eap-complete-causal-v1"
    report["scope"].append("AS completion reaches both CAK derivations through same-process order and exact RADIUS/EAP-Success messages. Timestamps remain capture sanity checks and do not generate causal links. Hostap/OpenSSL verification and instrumentation remain implementation observations.")
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
