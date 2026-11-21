"""Expose explicit laboratory security labels bound to retained device inventories."""
import hashlib
import json
from pathlib import Path

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "assignments", "decision", "coverage"]
LEAN_VIEW = "security_level_assignments"
SCOPE = "Explicit experimental security labels bound to retained Red-network and Inner-device inventories"


def read_profile_source(root, profile, kind):
    path = root / f"{profile['id']}-{kind}.json"
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == profile[kind + "Sha256"], "Policy source hash differs")
    return json.loads(raw)


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    declaration = json.loads((root / "policy.json").read_text())
    require(declaration["schema"] == "security-level-assignment/v1"
            and declaration["authority"] == "supervisor-selected-experimental-policy"
            and declaration["evidenceStatus"] == "declared"
            and declaration["realClassificationApproval"] is False,
            "Expected explicit experimental policy with no classification approval claim")
    profiles = declaration["profiles"]
    require(bool(profiles) and len({p["id"] for p in profiles}) == len(profiles),
            "Missing or duplicate policy profiles")
    devices, assignments, coverage = [], [], []
    raw_ids = {"policy": "policy.json"}
    for profile in profiles:
        name = profile["id"]
        require(isinstance(name, str) and name.isidentifier(), "Invalid policy profile ID")
        spec = read_profile_source(root, profile, "spec")
        snapshot = read_profile_source(root, profile, "snapshot")
        for kind in ["spec", "snapshot"]:
            raw_ids[name + "-" + kind] = f"{name}-{kind}.json"
        require(spec["name"] == profile["configurationId"]
                and snapshot["snapshot_id"] == profile["snapshotId"], "Policy identity differs")
        declared = {d["id"]: d for d in spec["devices"]}
        captured = {d["id"]: d for d in snapshot["devices"]}
        require(len(declared) == len(spec["devices"]) and len(captured) == len(snapshot["devices"])
                and set(declared) == set(captured), "Device inventory differs")
        inners = {k: d for k, d in declared.items() if d["role"] == "inner"}
        rows = profile["assignments"]
        require(bool(inners) and len(rows) == len(inners)
                and {r["innerDevice"] for r in rows} == set(inners), "Incomplete Inner assignment inventory")
        for row in rows:
            inner = inners[row["innerDevice"]]
            observed = captured[inner["id"]]
            require(observed["role"] == "inner" and observed["status"] == "observed"
                    and observed["observed_running"] is True
                    and row["profileLevel"] == inner["level"] == observed["security_level_id"]
                    and row["site"] == inner["site"] == observed["site"], "Unbound Inner assignment")
            require(row["network"] == inner["id"] + "/red-network", "Unbound Red network ID")
            level = row["assignedLevel"]
            require(set(level) == {"classification", "compartments", "dissemination", "otherControls"}
                    and isinstance(level["classification"], str) and bool(level["classification"].strip()),
                    "All four security dimensions must be explicit")
            for field in ["compartments", "dissemination", "otherControls"]:
                values = level[field]
                require(isinstance(values, list) and all(isinstance(x, str) and x.strip() for x in values)
                        and len(set(values)) == len(values), "Invalid security-label set")
            devices.append({"id": inner["id"], "role": "inner", "site": inner["site"], "profile": name})
            assignments.append(row | {"profile": name, "device": inner["id"], "evidenceStatus": "declared",
                                      "observation": "policy", "sourceSpec": name + "-spec",
                                      "sourceSnapshot": name + "-snapshot"})
        coverage.append({"profile": name, "innerDevices": len(inners), "assignedNetworks": len(rows),
                         "sourceSnapshotSha256": profile["snapshotSha256"]})
    require(len({r["device"] for r in assignments}) == len(assignments), "Duplicate cross-profile device")
    report = {"devices": devices, "assignments": assignments, "decision": [declaration], "coverage": coverage,
              "rawIds": raw_ids, "manifestSha256": manifest_hash, "projectionVersion": "security-level-assignment-v1",
              "scope": ["Explicit laboratory intent for the listed Red networks and Inner devices.",
                        "Snapshot profile labels identify the devices; assigned dimensions are new declared policy.",
                        "No recovered compartment state, certificate extension or real classification approval is claimed."]}
    return {"runtime_backend": "declared-experimental-policy"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    require(observation in report["rawIds"], "Unknown security-assignment source")
    return "" if stderr else (Path(directory) / report["rawIds"][observation]).read_text()


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)


def red_attachments(links, hosts, inners):
    attached = {}
    for first, second, observation in links:
        for host, peer in ((first, second), (second, first)):
            if host[0] not in hosts or host[1] != "red":
                continue
            require(peer[0] in inners and peer[1] == "red" and host[0] not in attached,
                    "Expected one direct Red host-to-Inner attachment")
            attached[host[0]] = (peer[0], observation)
    require(set(attached) == hosts, "Incomplete Red host attachments")
    return attached


def red_connectivity_profile(root, profile):
    spec = read_profile_source(root, profile, "spec")
    snapshot = read_profile_source(root, profile, "snapshot")
    devices = {device["id"]: device for device in spec["devices"]}
    require(set(snapshot["scope"]["expected_device_ids"]) == set(devices), "Incomplete snapshot device scope")
    placements = []
    for device in sorted(snapshot["devices"], key=lambda row: row["id"]):
        require(device["role"] == devices[device["id"]]["role"] and device["status"] == "observed"
                and device["observed_running"] is True and device["observation_ids"],
                "Unbound component placement observation")
        require(isinstance(device["host_id"], str) and device["host_id"].strip()
                and isinstance(device["virtualization_kind"], str) and device["virtualization_kind"].strip(),
                "Missing worker identity or virtualization kind")
        placements.append({"device": device["id"], "role": device["role"], "host": device["host_id"],
                           "virtualization": device["virtualization_kind"], "image": device["image_id"],
                           "observations": device["observation_ids"]})
    hosts = {key for key, device in devices.items() if device["role"] == "host"}
    labels = {row["innerDevice"]: row for row in profile["assignments"]}
    declared = red_attachments((
        ((link["a"]["device"], link["a"]["interface"]), (link["b"]["device"], link["b"]["interface"]), "")
        for link in spec["links"]), hosts, labels)
    observed = red_attachments((
        (*[iface.rsplit(":", 1) for iface in link["endpoint_interface_ids"]], link["id"])
        for link in snapshot["links"] if link["relation"] == "veth" and link["status"] == "observed"
        and link["runtime_peer_check"]["verified"] and link["runtime_peer_check"]["reciprocal_ifindex"]), hosts, labels)
    require({inner for inner, _ in declared.values()} == set(labels), "Missing declared Inner endpoint")
    network = {host: labels[inner]["network"] for host, (inner, _) in declared.items()}
    endpoints = [
        {"network": network[host], "host": host, "declaredInner": declared[host][0],
         "observedInner": observed[host][0], "link": observed[host][1], "site": devices[host]["site"],
         "profileLevel": devices[host]["level"], "assignedLevel": labels[declared[host][0]]["assignedLevel"]}
        for host in sorted(hosts)]
    peers = []
    for inner in sorted(labels):
        peer = devices[inner]["tunnel"]["peer"]
        require(peer in labels, "Unknown configured Inner peer")
        peers.append({"sourceInner": inner, "peerInner": peer, "sourceNetwork": labels[inner]["network"],
                      "peerNetwork": labels[peer]["network"]})
    probes = []
    for row in snapshot["probes"]:
        first, second = row["source_device"], row["destination_device"]
        require(first in hosts and second in hosts and row["status"] == "observed" and row["observation_ids"],
                "Unbound Red probe observation")
        require(row["expected_result"] in ("delivered", "no_reply") and
                row["observed_result"] in ("delivered", "no_reply"), "Unsupported Red probe result")
        probes.append({"source": network[first], "destination": network[second], "expected": row["expected_result"],
                       "observed": row["observed_result"], "id": row["id"], "observations": row["observation_ids"]})
    pairs = {(first, second) for first in network.values() for second in network.values() if first != second}
    require(len(probes) == len(pairs) and {(p["source"], p["destination"]) for p in probes} == pairs,
            "Red probes must cover each ordered distinct network pair exactly once")
    return {"solution": spec["name"], "endpoints": endpoints, "configuredPeers": peers, "probes": probes,
            "placements": placements,
            "profileSha256": profile["specSha256"], "snapshotSha256": profile["snapshotSha256"]}


def export_red_connectivity(directory, destination):
    _, labels = parse(directory)
    profiles = {p["id"]: red_connectivity_profile(Path(directory), p) for p in labels["decision"][0]["profiles"]}
    return export_report({"profiles": profiles, "manifestSha256": labels["manifestSha256"],
                          "projectionVersion": "red-connectivity-v1"}, destination, "red_connectivity")


EXTRA_EXPORTS = {"red_connectivity": export_red_connectivity}
