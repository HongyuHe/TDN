"""Independently check the two topology questions in the path-property trial."""

import argparse
from collections import deque
from itertools import combinations
import json
from time import perf_counter

from common import BASE, now, write_json


def reachable(adjacency, source, excluded):
    seen = {source}
    queue = deque([source])
    while queue:
        node = queue.popleft()
        for neighbor in adjacency[node]:
            if neighbor not in excluded and neighbor not in seen:
                seen.add(neighbor)
                queue.append(neighbor)
    return seen


def zone_graph(spec, zone):
    devices = {d["id"]: d for d in spec["devices"]}
    zones = {(d["id"], i["name"]): i.get("zone") for d in devices.values() for i in d["interfaces"]}
    edges = [(l["a"]["device"], l["b"]["device"]) for l in spec["links"]
             if zone is None or all(zones[(l[side]["device"], l[side]["interface"])] == zone for side in ("a", "b"))]
    adjacency = {d: set() for d in devices}
    for source, destination in edges:
        adjacency[source].add(destination)
        adjacency[destination].add(source)
    return devices, edges, adjacency


def check(spec, property_id):
    zone = "gray" if property_id == "P1" else None
    role = "gray-firewall" if property_id == "P1" else "firewall"
    devices, edges, adjacency = zone_graph(spec, zone)
    excluded = {name for name, d in devices.items() if d["role"] == role}
    if property_id == "P1":
        inners = [d for d in devices.values() if d["role"] == "inner"]
        pairs = [(a["id"], b["id"]) for a, b in combinations(inners, 2) if a["level"] != b["level"]]
    else:
        inners = [d for d in devices.values() if d["role"] == "outer"]
        black = [d for d in devices.values() if d["role"] == "transport"
                 and any(i.get("zone") == "black" for i in d["interfaces"])]
        pairs = [(a["id"], b["id"]) for a in inners for b in black]
    failures = []
    connected = []
    certificates = {}
    for source, destination in pairs:
        full = reachable(adjacency, source, set())
        remaining = reachable(adjacency, source, excluded)
        certificates[source] = sorted(remaining)
        if destination in full:
            connected.append([source, destination])
        if destination in remaining:
            failures.append([source, destination])
        assert all(b in remaining for a in remaining for b in adjacency[a] if b not in excluded)
    return {"property_id": property_id, "zone": zone, "edge_count": len(edges),
            "endpoint_pairs": len(pairs), "connected_pairs": connected,
            "excluded_firewalls": sorted(excluded), "reachable_sets_without_firewalls": certificates,
            "bypass_pairs": failures, "status": "inapplicable" if not pairs else "violated" if failures else "established",
            "scope": "Declared undirected device topology. P1 uses links with two Gray interfaces. P2 uses every declared link, including paths through other Outer devices. Device traversal conservatively permits all connections between that device's relevant interfaces.",
            "argument": "Each supplied reachable set contains its source and is closed under every edge that avoids the excluded firewalls. Induction on walk length keeps any firewall-free finite walk in that set. Every protected destination is outside that set."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("--output", default="supervisor-topology-reference.json")
    args = parser.parse_args()
    run = BASE / "runs" / args.run_id
    started = perf_counter()
    results = []
    for row in json.loads((run / "deployments.json").read_text()):
        for property_id in ("P1", "P2"):
            results.append({"network": row["id"], **check(row["spec"], property_id)})
    output = run / args.output
    if output.exists():
        raise ValueError("Reference already exists; preserve the original")
    write_json(output, {"recorded_at": now(), "elapsed_seconds": perf_counter() - started,
                        "method": "Independent reachability and closure checks, without reading Detector output", "results": results})
    print(json.dumps([{k: r[k] for k in ("network", "property_id", "status", "endpoint_pairs")} for r in results]))


if __name__ == "__main__":
    main()
