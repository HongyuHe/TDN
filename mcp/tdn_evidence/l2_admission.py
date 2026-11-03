"""Read captured, ordered netdev rules and bind them to Ethernet observations."""

import hashlib
import json
from pathlib import Path

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "interfaces", "l2_policies", "frames", "probes", "observations", "coverage"]
LEAN_VIEW = "l2_filter_admission"
SCOPE = "Untagged veth Ethernet, netdev ingress/egress and software MACsec; explicit bounded EAPOL framing"
COLLECTOR_SHA256 = "86bb4260ff2a2521cfec4aeac0da54cb0a17ddf95d79218c04c847f29982fa6d"
TAGGED_COLLECTOR_SHA256 = "ef228c6925ae126f9b2d01cc456fb486907aa2e5c8c33695da2ebbfa764b2655"
INCOMPLETE_TAGGED_COLLECTOR_SHA256 = "02eccc14e94e3e4a407c3890bbb4273ed0627b651076c31f1c5130da7aaa234b"


def one(rows, condition, message):
    selected = [row for row in rows if condition(row)]
    require(len(selected) == 1, message)
    return selected[0]


def match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def ether(field):
    return {"payload": {"protocol": "ether", "field": field}}


def raw_field(offset, length):
    return {"payload": {"base": "ll", "offset": offset, "len": length}}


def policy(document, sender, receiver, direction):
    records = document["nftables"]
    require(all(set(row) <= {"metainfo", "table", "chain", "rule"} for row in records),
            "Unsupported nft declaration")
    tables = [row["table"] for row in records if "table" in row]
    require(len(tables) == 1 and tables[0]["family"] == "netdev" and tables[0]["name"] == "tdn_l2",
            "Unexpected L2 table")
    chains = [row["chain"] for row in records if "chain" in row]
    require(len(chains) == 2 and {row["name"] for row in chains} == {"ingress", "egress"},
            "Unexpected L2 chains")
    for chain in chains:
        require(all(chain[key] == value for key, value in {
            "family": "netdev", "table": "tdn_l2", "type": "filter", "dev": "wire",
            "hook": chain["name"], "prio": -500, "policy": "drop"}.items()), "L2 hook or default differs")
    rules = [row["rule"] for row in records if "rule" in row and row["rule"]["chain"] == direction]
    require(len(rules) == 3 and [row.get("comment") for row in rules] ==
            ["bound-mka", "protected-unicast", "default-deny"], "Unexpected L2 rule order")
    require(sum("rule" in row for row in records) == 6, "Unexpected additional L2 rule")
    sci = int(sender.replace(":", "") + "0001", 16)
    offset = 4 if direction == "ingress" else 18
    lengths = [{"concat": [size, size + offset]} for size in range(32, 1497)]
    expected = [
        [match(ether("daddr"), "01:80:c2:00:00:03"), match(ether("saddr"), sender),
         match(ether("type"), 34958), match(raw_field(112, 16), 773),
         match({"concat": [raw_field(128, 16), {"meta": {"key": "length"}}]}, {"set": lengths}),
         match(raw_field(176, 64), sci)],
        [match(ether("daddr"), receiver), match(ether("saddr"), sender), match(ether("type"), 35045)], []]
    for index, (rule, conditions) in enumerate(zip(rules, expected)):
        require(rule["family"] == "netdev" and rule["table"] == "tdn_l2", "Rule belongs to another table")
        expressions = rule["expr"]
        require(expressions[:-2] == conditions and expressions[-1] ==
                ({"drop": None} if index == 2 else {"accept": None}), "L2 match or verdict differs")
        require(set(expressions[-2]) == {"counter"} and
                all(isinstance(expressions[-2]["counter"][key], int) and
                    expressions[-2]["counter"][key] >= 0 for key in ["packets", "bytes"]),
                "Missing L2 rule counter")
    source_address = int(sender.replace(":", ""), 16)
    destination_address = int(receiver.replace(":", ""), 16)
    control_destination = int("0180c2000003", 16)
    base = [{"protocol": {"name": "ethernet"}},
            {"ethernetHeaderBytes": {"bytes": 14}},
            {"sourceRange": {"low": source_address, "high": source_address}}]
    program = {"rules": [
        {"atoms": base + [{"destinationRange": {"low": control_destination, "high": control_destination}},
                          {"etherTypes": {"values": [34958]}}, {"mkaFraming": {"actorSCI": sci}},
                          {"payloadByteEquals": {"offset": 0, "value": 3}},
                          {"payloadBytesRange": {"low": 36, "high": 1500}}], "verdict": "allow"},
        {"atoms": base + [{"destinationRange": {"low": destination_address, "high": destination_address}},
                          {"etherTypes": {"values": [35045]}}], "verdict": "allow"},
        {"atoms": [], "verdict": "deny"}], "fallback": "deny"}
    return {"direction": direction, "interface": "wire", "priority": -500, "fallback": "deny",
            "sender": int(sender.replace(":", ""), 16), "receiver": int(receiver.replace(":", ""), 16),
            "actorSCI": sci, "controlDestination": int("0180c2000003", 16),
            "eapolVersion": 3, "eapolType": 5, "payloadLengthRange": [36, 1500],
            "declaredLengthPairs": [row["concat"] for row in lengths],
            "metaLengthIncludesEthernetHeader": direction == "egress",
            "derivedMKAFraming": {"actorSCI": sci},
            "orderedRules": rules,
            "program": program,
            "scope": "Exact selected nft expressions; additional payload size and version restrictions are retained"}


def counters(document):
    result = {}
    for entry in document["nftables"]:
        if "rule" not in entry:
            continue
        rule = entry["rule"]
        key = (rule["chain"], rule.get("comment"))
        require(key not in result, "Duplicate rule counter")
        result[key] = one(rule["expr"], lambda row: "counter" in row, "Missing rule counter")["counter"]
    return result


def frame_record(raw):
    offset, tags = 12, []
    while int.from_bytes(raw[offset:offset + 2], "big") == 33024:
        require(len(raw) >= offset + 6, "Truncated Ethernet VLAN header")
        tags.append(int.from_bytes(raw[offset + 2:offset + 4], "big"))
        offset += 4
    header = {"source": int.from_bytes(raw[6:12], "big"),
              "destination": int.from_bytes(raw[:6], "big"),
              "etherType": int.from_bytes(raw[offset:offset + 2], "big"), "vlanTags": tags}
    return {"header": header, "headerBytes": list(raw[:offset + 2]), "payload": list(raw[offset + 2:])}


def reconstructed_capture(record):
    captured = bytes.fromhex(record["capturedBytes"])
    auxiliary = record["packetAuxiliary"]
    require(auxiliary is not None and record["receiveFlags"] == 0,
            "Missing or truncated packet auxiliary metadata")
    require(auxiliary["length"] == auxiliary["snapLength"] == len(captured), "Capture length differs from metadata")
    if auxiliary["status"] & 16:
        require(auxiliary["status"] & 64 and 0 <= auxiliary["vlanTCI"] < 65536 and
                auxiliary["vlanTPID"] == 33024, "Unsupported stripped VLAN metadata")
        return captured[:12] + auxiliary["vlanTPID"].to_bytes(2, "big") + \
            auxiliary["vlanTCI"].to_bytes(2, "big") + captured[12:]
    return captured


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    collector = hashlib.sha256((root / "collector.source.py").read_bytes()).hexdigest()
    require(collector != INCOMPLETE_TAGGED_COLLECTOR_SHA256,
            "Tagged capture lacks packet auxiliary metadata and cannot establish full Ethernet headers")
    require(collector in {COLLECTOR_SHA256, TAGGED_COLLECTOR_SHA256},
            "Unreviewed L2 collector")
    document = json.loads((root / "observations.json").read_text())
    require(document["schema"] == "tdn-l2-admission/v1" and document["error"] is None and
            document["filtersBeforeAuthentication"] is True, "L2 collection or authentication ordering failed")
    commands = json.loads((root / "commands.json").read_text())
    by_id = {row["id"]: row for row in commands}
    require(len(by_id) == len(commands), "Duplicate L2 observation")
    namespaces, addresses = document["namespaces"], document["declaredLinkAddresses"]
    require(set(namespaces) == {"A", "B", "T", "X"} and set(addresses) == {"A", "B", "X"},
            "Incomplete L2 namespace inventory")

    def command(reference, node, argv):
        row = by_id[reference]
        require(row["device"] == node and row["returncode"] == 0 and row["command"] ==
                ["ip", "netns", "exec", namespaces[node], *argv], "Observation command binding differs")
        return row

    def filters(phase, node):
        row = command(phase[node]["filters"], node, ["nft", "-j", "-a", "list", "ruleset"])
        return json.loads(row["stdout"])

    final = json.loads((root / "final.json").read_text())
    pre = json.loads((root / "pre-authentication-filters.json").read_text())
    interfaces, policies, frames, observations = [], [], [], []
    for node, peer in [("A", "B"), ("B", "A")]:
        row = command(final[node]["interfaces"], node, ["ip", "-j", "-d", "address"])
        inventory = json.loads(row["stdout"])
        wire = one(inventory, lambda item: item["ifname"] == "wire", "Missing wire interface")
        require(wire["address"] == addresses[node] and wire["mtu"] == 1500 and
                wire["linkinfo"]["info_kind"] == "veth", "Unsupported Ethernet interface scope")
        require(all(item.get("linkinfo", {}).get("info_kind") != "vlan" for item in inventory),
                "VLAN interfaces require separate framing semantics")
        interfaces.extend({"device": node, "observation": row["id"], "record": item} for item in inventory)
        macsec = command(final[node]["macsec"], node, ["ip", "-s", "macsec", "show"])
        require(all(text in macsec["stdout"] for text in ["protect on validate strict", "encrypt on",
                "replay on window 0", "GCM-AES-256", "offload: off", "RXSC:"]), "MACsec state lacks required observations")
        startup = one(commands, lambda item: item["device"] == node and item.get("kind") == "process-start"
                      and any("wpa_supplicant" in word for word in item["command"]), "Missing MKA process start")
        require(by_id[pre[node]["filters"]]["endedAt"] < startup["startedAt"], "Filters installed after authentication")
        for direction, sender, receiver in [("ingress", peer, node), ("egress", node, peer)]:
            initial = policy(filters(pre, node), addresses[sender], addresses[receiver], direction)
            current = policy(filters(final, node), addresses[sender], addresses[receiver], direction)
            require(initial["derivedMKAFraming"] == current["derivedMKAFraming"], "MKA binding changed")
            policies.append(current | {"device": node, "observation": final[node]["filters"],
                                       "preAuthenticationObservation": pre[node]["filters"], "mtu": wire["mtu"]})
        capture = [json.loads(line) for line in (root / (node + "-frames.jsonl")).read_text().splitlines()]
        stats = one(capture, lambda row: row.get("recordType") == "captureStatistics", "Missing capture statistics")
        require(stats["drops"] == 0, "Frame capture reported drops")
        for index, record in enumerate(capture):
            if "recordType" in record:
                continue
            raw = bytes.fromhex(record["bytes"])
            if collector == TAGGED_COLLECTOR_SHA256:
                require(reconstructed_capture(record) == raw, "Reconstructed Ethernet frame differs from captured bytes and metadata")
            require(len(raw) >= 14 and record["sha256"] == hashlib.sha256(raw).hexdigest() and
                    record["source"] == raw[6:12].hex() and record["destination"] == raw[:6].hex() and
                    record["etherType"] == int.from_bytes(raw[12:14], "big"), "Ethernet frame metadata differs")
            decoded = frame_record(raw)
            frames.append(record | {"device": node, "observation": node + "-frames", "line": index + 1,
                                    "headerBytes": decoded["headerBytes"], "payloadBytes": decoded["payload"],
                                    "decodedHeader": decoded["header"], "leanFrame": decoded})
        observations.extend([{"id": node + "-frames", "device": node,
                              "record": {"stdout": (root / (node + "-frames.jsonl")).read_text(), "stderr": ""}},
                             {"id": node + "-wpa", "device": node,
                              "record": {"stdout": (root / (node + "-wpa.log")).read_text(), "stderr": ""}}])
    probes = []
    expected = {"unicast-A", "unicast-B", "egress-group-denied", "ingress-fresh-group-denied",
                "ingress-group-denied", "mka-wrong-actor", "mka-wrong-source", "mka-truncated", "mka-wrong-length"}
    if collector == TAGGED_COLLECTOR_SHA256:
        expected |= {"tagged-mka", "tagged-unicast"}
    require(len(document["probes"]) == len(expected) and {row["id"] for row in document["probes"]} == expected,
            "Missing L2 validation probe")
    for probe in document["probes"]:
        action = by_id[probe["commandObservation"]]
        require(action["returncode"] == probe["returncode"] == 0, "L2 probe command failed")
        deltas = []
        for node in ["A", "B"]:
            before, after = [counters(filters(probe[phase], node)) for phase in ["before", "after"]]
            require(set(before) == set(after), "Probe changed rule inventory")
            for key in before:
                change = {field: after[key][field] - before[key][field] for field in ["packets", "bytes"]}
                require(all(value >= 0 for value in change.values()), "Counter decreased")
                deltas.append({"device": node, "direction": key[0], "rule": key[1], **change})
        if probe["id"].startswith("unicast-"):
            source = probe["id"][-1]
            destination = "10.231.0.2" if source == "A" else "10.231.0.1"
            command(probe["commandObservation"], source, ["ping", "-n", "-c", "3", "-W", "1", destination])
            require("3 received" in action["stdout"] and "0% packet loss" in action["stdout"], "Positive traffic failed")
            require(all(row["packets"] == 3 for row in deltas if row["rule"] == "protected-unicast"),
                    "Positive traffic lacks L2 acceptance counters")
        else:
            node, direction, count = ("A", "egress", 1) if probe["id"] == "egress-group-denied" else (
                "B", "ingress", 1 if probe["id"] == "ingress-fresh-group-denied" else 3)
            dropped = one(deltas, lambda row: row["device"] == node and row["direction"] == direction and
                          row["rule"] == "default-deny", "Missing rejection counter")
            require(dropped["packets"] == count, "Negative probe did not reach deny rule")
            if count == 3:
                sent = json.loads(action["stdout"])
                argv = action["command"]
                require(len(argv) == 11 and argv[:4] == ["ip", "netns", "exec", namespaces["X"]] and
                        argv[5:10] == ["/lab/l2_admission_lab.py", "inject", "--interface", "wire", "--frame"],
                        "Injection command binding differs")
                raw = bytes.fromhex(argv[-1])
                require(len(raw) == sent["bytes"] and hashlib.sha256(raw).hexdigest() == sent["sha256"],
                        "Injection frame differs from send record")
                tagged = probe["id"] in {"tagged-mka", "tagged-unicast"}
                decoded = frame_record(raw)
                require(decoded["header"]["vlanTags"] == ([7] if tagged else []), "Unexpected injected VLAN tags")
                removed = 18 if tagged else 14
                require(sent["sent"] == 3 and dropped["bytes"] == 3 * (sent["bytes"] - removed),
                        "Ingress byte counter does not match observed header removal")
        probes.append(probe | {"counterChanges": deltas})
    observations.extend({"id": row["id"], "device": row["device"], "record": row} for row in commands)
    report = {"devices": [{"id": node, "role": document["roles"][node], "namespace": namespace}
                           for node, namespace in namespaces.items()],
              "interfaces": interfaces, "l2_policies": policies, "frames": frames, "probes": probes,
              "observations": observations, "coverage": [{"scope": text} for text in document["scope"] + [
                  "Permanent protected-network neighbors avoid an unmodeled ARP exception",
                  "Capture records an attempted frame, not by itself an accepted transmission",
                  "The test temporarily opens source egress only to exercise the destination ingress deny rule",
                  ("Tagged negative probes retain kernel VLAN auxiliary metadata and explicit header reconstruction"
                   if collector == TAGGED_COLLECTOR_SHA256 else
                   "This capture contains untagged probes only and records no VLAN auxiliary metadata"),
                  "No VLAN, MACsec hardware offload, universal Linux refinement or organization approval is inferred"]],
              "manifestSha256": manifest_hash, "scope": [SCOPE], "projectionVersion": "l2-filter-admission-v1"}
    return {"runtime_backend": "Linux-netdev-MACsec"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    row = one(report["observations"], lambda row: row["id"] == observation, "Unknown L2 observation")
    return row["record"]["stderr" if stderr else "stdout"]


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
