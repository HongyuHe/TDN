"""Expose physical MACsec captures without inferring protection from configuration."""

import hashlib
import json
from pathlib import Path
import re

from .eap import export_report, query_report
from .l2_admission import frame_record, reconstructed_capture
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "interfaces", "macsec_ports", "l2_policies", "frames", "cases", "observations", "coverage"]
LEAN_VIEW = "macsec_boundary"
SCOPE = "Isolated Linux MACsec physical-boundary cases with routed UDP, raw Ethernet and directional nft programs."
COLLECTOR_VERSIONS = {
    "96883d2376aa06ee625c41e4f2ff2e9a2a16090df1038523ae12c54361da9a5a": "three-case",
    "cdde31e1549e11bb9e2dc6db641037a42341e5cf1fadc16a2f167ae4d30ede47": "optional-integrity",
}
CAPTURE_SHA256 = "ef228c6925ae126f9b2d01cc456fb486907aa2e5c8c33695da2ebbfa764b2655"


def selected(rows, predicate, message):
    matches = [row for row in rows if predicate(row)]
    require(len(matches) == 1, message)
    return matches[0]


def link_programs(document, text):
    text = re.sub(r" # handle [0-9]+(?=\n|$)", "", text)
    rows = document["nftables"]
    require(all(set(row) <= {"metainfo", "table", "chain", "rule"} for row in rows), "Unsupported nft statement")
    tables = [row["table"] for row in rows if "table" in row]
    require(len(tables) == 1 and tables[0]["family"] == "netdev" and tables[0]["name"] == "tdn_boundary",
            "Unexpected physical filtering table")
    chains = [row["chain"] for row in rows if "chain" in row]
    require(len(chains) == 2 and {row["name"] for row in chains} == {"ingress", "egress"}, "Unexpected physical chains")
    rules = [row["rule"] for row in rows if "rule" in row]
    require(len(rules) == 4, "Unexpected physical rule count")
    output = []
    for direction in ["ingress", "egress"]:
        fallback = "accept" if direction == "ingress" else "drop"
        chain = selected(chains, lambda row: row["name"] == direction, "Missing directional chain")
        expected = {"family": "netdev", "table": "tdn_boundary", "type": "filter",
                    "hook": direction, "prio": -500, "policy": fallback}
        require(all(chain.get(key) == value for key, value in expected.items()), "Physical hook changed")
        if "dev" in chain:
            require(chain["dev"] == "wire", "Physical hook device changed")
        pattern = r"chain\s+" + direction + r"\s*\{\s*type filter hook " + direction + r' device "?wire"? priority -500; policy ' + fallback + r";"
        require(re.search(pattern, text) is not None, "Textual physical hook binding missing")
        directional = [row for row in rules if row["chain"] == direction]
        labels = ["incoming"] if direction == "ingress" else ["protected", "plaintext", "other"]
        require([row.get("comment") for row in directional] == labels, "Physical rule order changed")
        program, counts = [], {}
        for row in directional:
            require(row["family"] == "netdev" and row["table"] == "tdn_boundary", "Rule table changed")
            expressions = row["expr"]
            label = row["comment"]
            expected_match = []
            atoms = []
            if label in ["protected", "plaintext"]:
                ether_type = 35045 if label == "protected" else 2048
                represented = 35045 if label == "protected" else "ip"
                expected_match = [{"match": {"op": "==", "left": {"payload": {"protocol": "ether", "field": "type"}}, "right": represented}}]
                atoms = [{"protocol": {"name": "ethernet"}}, {"ethernetHeaderBytes": {"bytes": 14}},
                         {"etherTypes": {"values": [ether_type]}}]
            require(expressions[:-2] == expected_match and set(expressions[-2]) == {"counter"}, "Unsupported physical match")
            verdict = expressions[-1]
            require(verdict in [{"accept": None}, {"drop": None}], "Unsupported physical verdict")
            if label in ["incoming", "protected"]:
                require(verdict == {"accept": None}, "Required experiment allowance changed")
            if label == "other":
                require(verdict == {"drop": None}, "Unexpected experiment fallback")
            counter = expressions[-2]["counter"]
            require(set(counter) == {"packets", "bytes"} and all(type(value) is int and value >= 0 for value in counter.values()), "Invalid filter counter")
            counts[label] = counter
            program.append({"atoms": atoms, "verdict": "allow" if "accept" in verdict else "deny"})
        output.append({"direction": direction, "interface": "wire", "priority": -500,
                       "program": {"rules": program, "fallback": "allow" if fallback == "accept" else "deny"},
                       "counters": counts, "orderedRules": directional})
    return output


def decoded_frame(row):
    raw = reconstructed_capture(row)
    require(raw.hex() == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"], "Captured frame hash differs")
    require(len(raw) >= 14 and int.from_bytes(raw[12:14], "big") in {2048, 35045}, "Unsupported experiment Ethernet type")
    require(row["source"] == raw[6:12].hex() and row["destination"] == raw[:6].hex()
            and row["etherType"] == int.from_bytes(raw[12:14], "big"), "Captured header fields differ")
    result = frame_record(raw)
    require(result["header"]["vlanTags"] == [], "Tagged boundary experiment unsupported")
    if row["etherType"] == 2048:
        packet = raw[14:]
        require(len(packet) >= 28 and packet[0] == 69 and packet[9] == 17
                and int.from_bytes(packet[6:8], "big") & 0x3FFF == 0, "Unsupported UDP packet shape")
        size = int.from_bytes(packet[2:4], "big")
        udp_size = int.from_bytes(packet[24:26], "big")
        require(size == len(packet) and udp_size == size - 20, "Packet lengths differ")
        result["ipv4"] = {"source": int.from_bytes(packet[12:16], "big"),
                          "destination": int.from_bytes(packet[16:20], "big"),
                          "identification": int.from_bytes(packet[4:6], "big"), "ttl": packet[8],
                          "sourcePort": int.from_bytes(packet[20:22], "big"),
                          "destinationPort": int.from_bytes(packet[22:24], "big"),
                          "payloadHex": packet[28:].hex()}
    else:
        payload = raw[14:]
        require(len(payload) >= 30 and payload[0] & 32 != 0, "Missing explicit MACsec SCI")
        result["macsec"] = {"tciAN": payload[0], "an": payload[0] & 3,
                            "pn": int.from_bytes(payload[2:6], "big"),
                            "sci": int.from_bytes(payload[6:14], "big")}
    return result


def associations(text):
    direction, sci, records = None, None, []
    for line in text.splitlines():
        channel = re.search(r"(TXSC|RXSC): ([0-9a-f]{16})", line)
        if channel:
            direction = "tx" if channel[1] == "TXSC" else "rx"
            sci = int(channel[2], 16)
        association = re.match(r"\s+([0-3]): PN ([0-9]+), state (on|off), key ([0-9a-f]{32})$", line)
        if association:
            require(direction is not None, "Association has no channel")
            records.append({"direction": direction, "sci": sci, "an": int(association[1]),
                            "pn": int(association[2]), "active": association[3] == "on",
                            "publicKeyIdentifier": association[4]})
    require(len(records) == 2 and {row["direction"] for row in records} == {"tx", "rx"},
            "Incomplete association inventory")
    return records


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    collector_hash = hashlib.sha256((root / "collector.source.py").read_bytes()).hexdigest()
    require(collector_hash in COLLECTOR_VERSIONS, "Unreviewed MACsec boundary collector")
    require(hashlib.sha256((root / "capture.source.py").read_bytes()).hexdigest() == CAPTURE_SHA256,
            "Unreviewed physical packet capture")
    document = json.loads((root / "observations.json").read_text())
    require(document["schema"] == "tdn-macsec-boundary/v1" and document["error"] is None, "Incomplete MACsec boundary collection")
    require(set(document["namespaces"]) == {"R", "A", "B"} and all(document["cleanup"].values()), "Invalid namespace inventory or cleanup")
    sequences = [["protected", "unprotected-allowed", "unprotected-denied"]]
    if COLLECTOR_VERSIONS[collector_hash] == "optional-integrity":
        sequences.append(["protected", "integrity-only", "unprotected-allowed", "unprotected-denied"])
    require([case["id"] for case in document["cases"]] in sequences, "Missing boundary cases")
    raw_commands = json.loads((root / "commands.json").read_text())
    by_id = {row["id"]: row for row in raw_commands}
    require(len(by_id) == len(raw_commands), "Duplicate command identities")
    require(all(row.get("returncode", 0) == 0 for row in raw_commands), "A collection command failed")
    observations = [{"id": row["id"], "device": row["node"], "record": row} for row in raw_commands]

    def observation(reference, node, command):
        row = by_id[reference]
        require(row["node"] == node and row["command"] == ["ip", "netns", "exec", document["namespaces"][node], *command], "Command observation binding differs")
        return row["stdout"]

    interfaces, macsec_ports, policies, frames, cases = [], [], [], [], []
    for case in document["cases"]:
        case_id = case["id"]
        captured = []
        policy_lookup = {}
        link_lookup = {}
        for phase in ["before", "after"]:
            for node in ["R", "A", "B"]:
                references = case[phase][node]
                links = json.loads(observation(references["links"], node, ["ip", "-j", "-s", "-d", "link"]))
                link_lookup[phase, node] = {row["ifname"]: row for row in links}
                for interface in links:
                    interfaces.append({"case": case_id, "phase": phase, "device": node,
                                       "observation": references["links"], "record": interface})
                forwarding = observation(references["forwarding"], node, ["sysctl", "-n", "net.ipv4.ip_forward"])
                if node == "A":
                    require(forwarding.strip() == "1", "Source routing is not enabled")
                if node in ["A", "B"]:
                    mac = selected(links, lambda row: row["ifname"] == "mac0", "Missing logical MACsec port")
                    physical = selected(links, lambda row: row["ifname"] == "wire", "Missing physical port")
                    require(mac.get("link") == "wire" and mac["linkinfo"]["info_kind"] == "macsec"
                            and "UP" in mac["flags"], "MACsec parent binding differs")
                    association_text = observation(references["macsec"], node, ["ip", "-s", "macsec", "show"])
                    parsed_associations = associations(association_text)
                    require(next(row for row in parsed_associations if row["direction"] == "tx")["sci"] ==
                            int(mac["linkinfo"]["info_data"]["sci"], 16), "MACsec SCI observations differ")
                    macsec_ports.append({"case": case_id, "phase": phase, "device": node,
                                         "logicalName": "mac0", "logicalIndex": mac["ifindex"],
                                         "physicalName": "wire", "physicalIndex": physical["ifindex"],
                                         "settings": mac["linkinfo"]["info_data"], "flags": mac["flags"],
                                         "observation": references["links"], "associationObservation": references["macsec"],
                                         "associations": association_text, "associationRecords": parsed_associations})
                    raw_json = json.loads(observation(references["filters"], node, ["nft", "-j", "-a", "list", "ruleset"]))
                    raw_text = observation(references["filtersText"], node, ["nft", "-a", "list", "ruleset"])
                    for policy in link_programs(raw_json, raw_text):
                        policy |= {"case": case_id, "phase": phase, "device": node,
                                   "observation": references["filters"], "deviceObservation": references["filtersText"]}
                        policies.append(policy)
                        policy_lookup[phase, node, policy["direction"]] = policy
            for left, right in document["physicalLinks"]:
                left_node, left_name = left.split(":")
                right_node, right_name = right.split(":")
                first, second = link_lookup[phase, left_node][left_name], link_lookup[phase, right_node][right_name]
                require(first["link_index"] == second["ifindex"] and second["link_index"] == first["ifindex"], "Physical peer indices differ")
        require(set(case["captures"]) == {"R", "A", "B"} and case["deliveries"] == case_id + "-deliveries.jsonl",
                "Capture file inventory differs")
        for node, filename in case["captures"].items():
            require(filename == case_id + "-" + node + "-frames.jsonl", "Capture file identity differs")
            rows = [json.loads(line) for line in (root / filename).read_text().splitlines() if line.startswith("{")]
            stats = [row for row in rows if row.get("recordType") == "captureStatistics"]
            data = [row for row in rows if "bytes" in row]
            require(len(stats) == 1 and stats[0]["drops"] == 0 and stats[0]["packets"] == len(data), "Incomplete physical capture")
            for index, row in enumerate(data):
                require(row["interface"] in link_lookup["before", node] and row["packetType"] in [0, 4],
                        "Captured interface or direction is unknown")
                decoded = decoded_frame(row)
                if "ipv4" in decoded:
                    require(decoded["ipv4"]["payloadHex"] == document["payloadHex"], "Application payload changed")
                frame = {"id": case_id + ":" + node + ":" + str(index), "case": case_id,
                         "device": node, "interface": row["interface"], "packetType": row["packetType"],
                         "monotonicNs": row["monotonicNs"], "rawFile": filename, "sha256": row["sha256"],
                         "bytes": row["bytes"], **decoded}
                frames.append(frame)
                captured.append(frame)
            observations.append({"id": "file:" + filename, "device": node, "file": filename})
        for node in ["A", "B"]:
            earlier = link_lookup["before", node]["mac0"]
            later = link_lookup["after", node]["mac0"]
            require(earlier["linkinfo"] == later["linkinfo"] and earlier["flags"] == later["flags"],
                    "MACsec settings changed during the case")
            for direction in ["ingress", "egress"]:
                require(policy_lookup["before", node, direction]["program"] == policy_lookup["after", node, direction]["program"],
                        "Physical filter changed during the case")
        deliveries = [json.loads(line) for line in (root / case["deliveries"]).read_text().splitlines() if line.startswith("{")]
        require(all(row["payload"] == document["payloadHex"] for row in deliveries), "Delivered payload differs")
        observations.append({"id": "file:" + case["deliveries"], "device": "B", "file": case["deliveries"]})
        before = policy_lookup["before", "A", "egress"]["counters"]
        after = policy_lookup["after", "A", "egress"]["counters"]
        delta = {label: {key: after[label][key] - before[label][key] for key in ["packets", "bytes"]} for label in before}
        require(all(value >= 0 for count in delta.values() for value in count.values()), "Counters decreased within a case")
        sent_physical = [row for row in captured if row["device"] == "A" and row["interface"] == "wire" and row["packetType"] == 4]
        received_physical = [row for row in captured if row["device"] == "B" and row["interface"] == "wire" and row["packetType"] == 0]
        pairs = []
        for received in received_physical:
            sent = selected(sent_physical, lambda row: row["sha256"] == received["sha256"],
                            "Physical receiver frame has no unique sender capture")
            pairs.append({"send": sent["id"], "receive": received["id"], "sha256": sent["sha256"]})
        cases.append({"id": case_id, "device": "A", "sendObservation": case["sendObservation"],
                      "receiverPhysicalFrames": [row["id"] for row in captured if row["device"] == "B" and row["interface"] == "wire"],
                      "sourceArrivalFrames": [row["id"] for row in captured if row["device"] == "A" and row["interface"] == "red"],
                      "logicalTransmitFrames": [row["id"] for row in captured if row["device"] == "A" and row["interface"] == "mac0"],
                      "deliveredPayloads": len(deliveries), "senderEgressCounterDeltas": delta,
                      "physicalFramePairs": pairs,
                      "before": case["before"], "after": case["after"]})
    report = {"devices": [{"id": node, "namespace": namespace, "role": document["roles"][node]} for node, namespace in document["namespaces"].items()],
              "interfaces": interfaces, "macsec_ports": macsec_ports, "l2_policies": policies,
              "frames": frames, "cases": cases, "observations": observations,
              "coverage": [{"cases": len(cases), "scope": document["scope"], "payloadHex": document["payloadHex"]}],
              "physicalLinks": document["physicalLinks"], "macsecParents": document["macsecParents"],
              "scope": document["scope"], "manifestSha256": manifest_hash, "projectionVersion": "macsec-boundary-v1"}
    return {"runtime_backend": "Linux-network-namespaces", "started_at": document["startedAt"], "ended_at": document["endedAt"]}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    row = selected(report["observations"], lambda row: row["id"] == observation, "Unknown MACsec boundary observation")
    if "file" in row:
        return "" if stderr else (Path(directory) / row["file"]).read_text()
    return row["record"].get("stderr" if stderr else "stdout", "")


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
