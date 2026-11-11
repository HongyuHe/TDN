from pathlib import Path
import argparse
from collections import defaultdict, deque
import copy
import hashlib
import json

parser = argparse.ArgumentParser(description="Build MACsec authentication fixtures from retained public evidence.")
parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[2])
parser.add_argument("--input-dir", type=Path, default=Path("data/evidence/macsecAuthentication"))
parser.add_argument("--mapping", type=Path)
parser.add_argument("--base-profiles", type=Path, default=Path("data/evidence/macsecProtection/MacsecProtectionProfiles.json"))
parser.add_argument("--output-dir", type=Path, default=Path("data/evidence/macsecAuthentication"))
args = parser.parse_args()
root = args.project_root.resolve()
input_dir = (root / args.input_dir).resolve()
source_dir = input_dir / "exports"
mapping_path = (root / args.mapping).resolve() if args.mapping else input_dir / "CompletionFieldMap.json"
base_profiles = (root / args.base_profiles).resolve()
output = (root / args.output_dir).resolve()
output.mkdir(parents=True, exist_ok=True)
profiles = json.loads(base_profiles.read_text())
mapping = json.loads(mapping_path.read_text())

def input_identity(path):
    try:
        name = str(path.relative_to(root))
        base = "project-root"
    except ValueError:
        name = str(path)
        base = "absolute"
    return {"path": name, "pathBase": base, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
reports = {}
provenance = {"schema": "macsec-authentication-v1",
    "inputs": {"baseProfiles": input_identity(base_profiles),
               "completionFieldMap": input_identity(mapping_path), "exports": {}},
    "captures": {}, "curated": [
    "Red source addressing, forwarding routes, security/site labels and modeled Ethernet payloads are model fixtures.",
    "The AS has one modeled Gray management attachment at central-site; interface identity and role follow the captured deployment.",
    "The reverse transit-router is an unused one-interface attachment with no route or allowed traffic origin. The ten-step trace starts at P0:red, routes to P0's MACsec interface and crosses P0/P1 only.",
    "SA material is a distinct 32-byte synthetic model value per capture, indexed by the observed opaque SAK SHA-256 reference. No captured secret bytes are claimed.",
    "TLS and backend primitives are table adapters for the two observed successful exchanges. Crypto implementation correctness remains external.",
    "Causal edges use process order and exact public message matching. Numeric event positions are a topological enumeration, never clock order."]}
key = lambda event: (event["device"], event["observation"], event["line"])

def renamed(value, names):
    if isinstance(value, str):
        for old, new in names.items():
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [renamed(item, names) for item in value]
    if isinstance(value, dict):
        return {k: renamed(v, names) for k, v in value.items()}
    return value

for direction, topology in [("forward", "direct"), ("reverse", "routed")]:
    plan = mapping[direction]
    collection = plan["collection"]
    path = source_dir / (collection + "-authentication_complete_history.json")
    identity = input_identity(path)
    assert identity["sha256"] == plan["export_sha256"], "Export differs from retained source mapping"
    provenance["inputs"]["exports"][direction] = identity
    report = json.loads(path.read_text())
    assert report["manifestSha256"] == plan["manifest_sha256"], "Capture manifest binding differs"
    raw_dir = output / "exports"
    raw_dir.mkdir(exist_ok=True)
    (raw_dir / path.name).write_bytes(path.read_bytes())
    auth = report["authentication"][0]
    exchange = report["exchanges"][0]
    profile = copy.deepcopy(profiles[topology])
    old_names = profile["ownerNames"]
    names = dict(zip(old_names, ["P0", "P1", "transit-router"]))
    profile = renamed(profile, names)
    sci = {peer["device"]: int(next(i for i in peer["installed"] if i["direction"] == "transmit")["sci"], 16)
           for peer in auth["peers"]}
    old_to_new = {}
    for iface in profile["macIfaces"]:
        owner = profile["ownerNames"][profile["ifaceData"][iface["physicalIface"]]["owner"]]
        old_to_new[iface["transmitAssociation"]["sci"]] = sci[owner]
    for iface in profile["macIfaces"]:
        iface["transmitAssociation"]["sci"] = old_to_new[iface["transmitAssociation"]["sci"]]
        for association in iface["receiveAssociations"]:
            association["sci"] = old_to_new[association["sci"]]
    for peer in profile["mkaPeers"]:
        peer["actorSCI"] = old_to_new[peer["actorSCI"]]
    for association, frame in profile["macFrames"]:
        association["sci"] = old_to_new[association["sci"]]
        source_address = association["sci"] >> 16
        receiver = next(value for value in sci.values() if value != association["sci"])
        destination_address = receiver >> 16
        frame["header"]["source"] = source_address
        frame["header"]["destination"] = destination_address
        frame["headerBytes"] = list(destination_address.to_bytes(6, "big") + source_address.to_bytes(6, "big") + b"\x88\xe5")
        frame["payload"][6:14] = list(association["sci"].to_bytes(8, "big"))
    for interface in profile["interfaces"]:
        if interface["device"] in sci:
            interface["linkAddress"] = sci[interface["device"]] >> 16
    sak = plan["sak_reference"]
    for tunnel in profile["tunnels"]:
        tunnel["id"] = direction + ":" + tunnel["sender"] + "-to-" + tunnel["receiver"]
        tunnel["keyContext"] = sak
    for peer in profile["mkaPeers"]:
        owner = profile["ownerNames"][profile["ifaceData"][peer["sourceIface"]]["owner"]]
        peer["tunnel"] = next(t["id"] for t in profile["tunnels"] if t["sender"] == owner)
    as_owner = len(profile["ownerNames"])
    profile["ownerNames"].append("AS")
    as_data = copy.deepcopy(profile["deviceData"][0])
    as_data["localAddresses"] = [173539330]
    as_data["ifaceSecurityDomain"] = None
    profile["deviceData"].append(as_data)
    profile["devices"].append({"id": "AS", "site": "central-site", "kind": "authenticationServer",
                               "layer": None, "level": profile["devices"][0]["level"], "infrastructure": True})
    for device in profile["devices"]:
        if device["id"] == auth["authenticator"]:
            device["site"] = "central-site"
    control = len(profile["ifaceData"])
    peer_owner = profile["ownerNames"].index(auth["authenticator"])
    for owner, name, address in [(peer_owner, auth["authenticator"] + ":management", 173539329),
                                 (as_owner, "AS:eth0", 173539330)]:
        profile["ifaceData"].append({"owner": owner, "name": name, "stack": [], "canOriginateTraffic": False})
        profile["interfaces"].append({"id": name, "device": profile["ownerNames"][owner], "zone": "gray",
          "address": address, "namespaceAddresses": [], "linkAddress": None, "physical": True,
          "externalData": False, "managementNetwork": True, "mtu": 1500})
    profile["links"].extend([[control, control + 1], [control + 1, control]])
    anchors = {key(value): name for name, value in plan["anchors"].items()}
    installations = {key(item["record"]): item for item in plan["installations"]}
    paths = list(plan["historical_eap_paths"].values()) + [i["issued_to_installed_path"] for i in plan["installations"]]
    used_edges = {(key(a), key(b)) for route in paths for a, b in zip(route, route[1:])}
    message_edges = [edge for edge in report["causal_links"] if edge["kind"] == "matching_message"
                     and (key(edge["before"]), key(edge["after"])) in used_edges]
    messages = {m["sha256"]: m for m in report["mka_messages"] + report["completion_messages"]}
    retained = set(anchors) | set(installations)
    message_nodes = {}
    for edge in message_edges:
        first, last = key(edge["before"]), key(edge["after"])
        retained.update([first, last])
        message = messages[edge["messageSha256"]]
        raw = bytes.fromhex(message["hex"])
        assert hashlib.sha256(raw).hexdigest() == edge["messageSha256"]
        for node, kind in [(first, "send"), (last, "receive")]:
            assert node not in message_nodes and node not in anchors and node not in installations
            message_nodes[node] = {"kind": kind, "sender": first[0], "receiver": last[0], "message": list(raw)}
    edges = set()
    for route in paths:
        nodes = [key(event) for event in route if key(event) in retained]
        edges.update(zip(nodes, nodes[1:]))
    for first, last in edges:
        if first[:2] == last[:2]:
            assert first[2] < last[2]
        else:
            assert any(key(e["before"]) == first and key(e["after"]) == last for e in message_edges)
    successors = defaultdict(list)
    indegree = {node: 0 for node in retained}
    for first, last in edges:
        successors[first].append(last)
        indegree[last] += 1
    ready = sorted(node for node, degree in indegree.items() if degree == 0)
    ordered = []
    while ready:
        node = ready.pop(0)
        ordered.append(node)
        for following in sorted(successors[node]):
            indegree[following] -= 1
            if indegree[following] == 0:
                ready.append(following)
                ready.sort()
    assert len(ordered) == len(retained)
    rank = {node: i for i, node in enumerate(ordered)}
    epoch = collection + ":" + report["manifestSha256"]
    history_records = []
    for node in ordered:
        record = {"position": rank[node], "component": node[0], "observer": collection + ":" + node[1],
          "localPosition": node[2], "source": "evidence://" + collection + "/raw/" + node[1] + "#line=" + str(node[2]),
          "kind": "", "sender": "", "receiver": "", "message": [], "installation": ""}
        if node in message_nodes:
            record.update(message_nodes[node])
        elif node in anchors:
            record["kind"] = {"verified": "verified", "delivered": "delivered", "supplicantDerived": "derived",
                "authenticatorDerived": "derived", "authenticated": "authenticated", "issued": "issued"}[anchors[node]]
        else:
            record["kind"] = "installed"
            record["installation"] = installations[node]["proposed_installation_id"]
        history_records.append(record)
    def route(first, last):
        pending = deque([(key(first), [])])
        visited = {key(first)}
        while pending:
            node, previous = pending.popleft()
            if node == key(last):
                return [rank[n] for n in previous]
            for following in sorted(successors[node]):
                if following not in visited:
                    visited.add(following)
                    pending.append((following, previous + [following]))
        raise RuntimeError("missing retained causal path")
    material = [160 if direction == "forward" else 176] * 32
    setup = []
    for index, iface in enumerate(profile["macIfaces"]):
        owner = profile["ifaceData"][iface["physicalIface"]]["owner"]
        device = profile["ownerNames"][owner]
        item = next(i for i in plan["installations"] if i["record"]["device"] == device and i["record"]["direction"] == "transmit")
        peer = auth["supplicant"]
        anchors_by_name = plan["anchors"]
        installation = {"device": owner, "association": iface["transmitAssociation"], "epoch": epoch,
          "installation": item["proposed_installation_id"], "source": item["proposed_source"],
          "installedAt": rank[key(item["record"])], "issuedAt": rank[key(anchors_by_name["issued"])],
          "issuer": auth["authenticator"], "peer": peer, "session": exchange["sessionHex"], "keyReference": sak}
        row = {"installation": installation, "authenticationIndex": index, "tunnelIndex": index,
          "exchangeIndex": 0 if direction == "forward" else 1, "material": material}
        row.update({name: rank[key(anchors_by_name[name])] for name in
                    ["authenticated", "verified", "delivered", "supplicantDerived", "authenticatorDerived"]})
        for name, first, last in [("issuancePath", "authenticated", "issued"),
          ("verifiedToDelivered", "verified", "delivered"), ("verifiedToSupplicant", "verified", "supplicantDerived"),
          ("deliveredToAuthenticator", "delivered", "authenticatorDerived"),
          ("supplicantToAuthenticated", "supplicantDerived", "authenticated"),
          ("authenticatorToAuthenticated", "authenticatorDerived", "authenticated")]:
            row[name] = route(anchors_by_name[first], anchors_by_name[last])
        row["installationPath"] = route(anchors_by_name["issued"], item["record"])
        setup.append(row)
    level = profile["devices"][0]["level"]
    identity = {"domain": level, "issuer": exchange["trustAnchorSha256"], "trustedIssuers": [exchange["trustAnchorSha256"]]}
    tls_input = {"session": exchange["sessionHex"], "device": auth["supplicant"], "server": "AS",
      "deviceCertificate": exchange["deviceCertificateSha256"], "serverCertificate": exchange["serverCertificateSha256"],
      "deviceIdentity": identity, "serverIdentity": identity, "transcript": list(bytes.fromhex(exchange["transcriptHex"])),
      "deviceNonce": list(bytes.fromhex(exchange["deviceNonceHex"])), "serverNonce": list(bytes.fromhex(exchange["serverNonceHex"])),
      "role": "supplicant"}
    backend_input = {"session": exchange["sessionHex"], "server": "AS", "authenticator": auth["authenticator"],
      "supplicant": auth["supplicant"], "masterSessionKey": exchange["masterSessionKeyReference"],
      "channelBinding": list(bytes.fromhex(exchange["channelBindingHex"])),
      "protectedRecord": list(bytes.fromhex(exchange["protectedRecordHex"])),
      "nonce": list(bytes.fromhex(exchange["backendNonceHex"]))}
    reports[direction] = {"profile": profile, "collection": collection, "epoch": epoch,
      "session": exchange["sessionHex"], "keyServer": auth["authenticator"],
      "cak": plan["cak_reference"], "sak": sak, "material": material,
      "tlsInput": tls_input, "masterSessionKey": exchange["masterSessionKeyReference"],
      "backendInput": backend_input, "historyRecords": history_records,
      "dependencies": sorted([[rank[a], rank[b]] for a, b in edges]), "setupRecords": setup}
    provenance["captures"][direction] = {"collection": collection, "export": "exports/" + path.name,
      "exportSha256": hashlib.sha256(path.read_bytes()).hexdigest(), "manifestSha256": report["manifestSha256"],
      "retainedRawNodes": [{"position": rank[n], "device": n[0], "observation": n[1], "line": n[2]} for n in ordered],
      "retainedEdges": [{"before": rank[a], "after": rank[b], "kind": "process_order" if a[:2] == b[:2] else "matching_message"}
                         for a, b in sorted(edges)], "sourceMap": input_identity(mapping_path)}
(output / "MacsecAuthenticationProfiles.json").write_text(json.dumps(reports, separators=(",", ":")) + "\n")
(output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
print(json.dumps({name: {"historyRecords": len(value["historyRecords"]), "dependencies": len(value["dependencies"]),
    "devices": len(value["profile"]["devices"]), "ifaces": len(value["profile"]["ifaceData"]),
    "tlsTranscriptBytes": len(value["tlsInput"]["transcript"]), "setupRecords": len(value["setupRecords"])}
    for name, value in reports.items()}, indent=2))
