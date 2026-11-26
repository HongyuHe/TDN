"""Apply the Gray Firewall connection requirement to observed interface peers."""

import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from attachment_view import from_native
from measure import typecheck
from mode_lab import profile
from observe_controls import HERE, NETWORKS


SOURCE = HERE / "GrayConnectivityChecks.lean"


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def observed_graph(declared, census, missing_ports=()):
    devices = declared["topology"]["devices"]
    expected = {d["id"]: d for d in devices}
    rows = {d["device"]: d for d in census["devices"]}
    if set(rows) != set(expected) or not all(d["interfaces_ok"] for d in rows.values()):
        raise ValueError(
            "The firewall proof needs a complete interface census on every device"
        )
    ports = {}
    for name, row in rows.items():
        known = {p["name"]: p for p in expected[name]["interfaces"]}
        if row["role"] != expected[name]["role"]:
            raise ValueError(f"Role mismatch on {name}")
        for port in row["interfaces"]:
            if port.get("link_index") is None:
                continue
            key = (name, port["ifname"])
            if port["ifname"] not in known or key in ports:
                raise ValueError(f"Unexpected linked interface {key}")
            ports[key] = port
    assigned = set()
    links = []
    missing = set()
    for edge in declared["topology"]["links"]:
        first, second = ((edge[k]["device"], edge[k]["interface"]) for k in ("a", "b"))
        if first in assigned or second in assigned:
            raise ValueError("An interface appears in multiple declared connections")
        assigned.update((first, second))
        a, b = ports.get(first), ports.get(second)
        if a is None or b is None:
            missing.update(
                end for end, actual in ((first, a), (second, b)) if actual is None
            )
            continue
        if a["link_index"] != b["ifindex"] or b["link_index"] != a["ifindex"]:
            raise ValueError("Observed peer identifiers disagree on " + str(edge))
        if all(
            next(p["zone"] for p in expected[name]["interfaces"] if p["name"] == iface)
            == "gray"
            for name, iface in (first, second)
        ):
            links.extend([(first[0], second[0]), (second[0], first[0])])
    if set(ports) - assigned or missing != set(missing_ports):
        raise ValueError(
            "The observed topology differs from the designated, independently recorded interface change"
        )
    return sorted(set(links))


def paths_from(start, edges):
    adjacent = defaultdict(list)
    for a, b in edges:
        adjacent[a].append(b)
    paths = {start: [start]}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for other in adjacent[node]:
            if other not in paths:
                paths[other] = paths[node] + [other]
                queue.append(other)
    return paths


def evidence(declared, census, missing=()):
    edges = observed_graph(declared, census, missing)
    devices = declared["topology"]["devices"]

    def names(role):
        return sorted(d["id"] for d in devices if d["role"] == role)

    inners, outers, firewalls = names("inner"), names("outer"), names("gray-firewall")
    if not all((inners, outers, firewalls)):
        raise ValueError("The original network must contain all three device roles")
    witnesses = []
    regions = []
    for firewall in firewalls:
        reachable = paths_from(firewall, edges)
        inside = [p for d, p in reachable.items() if d in inners]
        outside = [p for d, p in reachable.items() if d in outers]
        if not inside:
            regions.append({"firewall": firewall, "members": sorted(reachable)})
        if inside and outside:
            left = min(inside, key=lambda p: (len(p), p))
            right = min(outside, key=lambda p: (len(p), p))
            witnesses.append(
                {
                    "firewall": firewall,
                    "inner": left[-1],
                    "outer": right[-1],
                    "toFirewall": left[::-1],
                    "fromFirewall": right,
                }
            )
    return {
        "edges": edges,
        "inners": inners,
        "outers": outers,
        "firewalls": firewalls,
        "paths": witnesses,
        "regions": regions,
    }


def verify(folder, data):
    if (folder / "result.json").exists():
        proof = read(folder / "result.json")
        loaded = read(folder / "evidence.json")
        if (
            loaded != json.loads(json.dumps(data))
            or proof["source_sha256"] != hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        ):
            raise ValueError("Existing proof or capture differs")
        return proof
    return typecheck(SOURCE, folder, data, set(SOURCE.read_text().splitlines()))


def clean(root, n):
    native = root / "raw" / "controls" / n / "snapshot/native"
    p = profile(n)
    data = evidence(p, from_native(p, native))
    from full_suite import graph_input

    graph = graph_input(native)
    devices = read(native / "snapshot.json")["devices"]
    official = {(devices[a]["id"], devices[b]["id"]) for a, b in graph["gray_edges"]}
    if set(data["edges"]) != official:
        raise ValueError("New and existing observed Gray graphs differ")
    return verify(root / "controls" / (n + "-gray-paths"), data)


def trial(root, case):
    name, family = case.name, case.parent.name
    if name not in NETWORKS:
        raise ValueError("Unexpected network")
    p = profile(name)
    raw = root / "raw/trials" / family / name
    detached = family in (
        "firewall-inside-disconnected",
        "firewall-outside-disconnected",
    )
    missing = set()
    if detached:
        change = read(case / "change.json")
        missing = {(change["device"], port) for port in change["ports"]}
    if detached and (case / "snapshot.json").is_file():
        census = read(case / "snapshot.json")
    else:
        if (
            not (raw / "capture.json").is_file()
            or not read(raw / "capture.json")["converged"]
        ):
            write(
                case / "gray-paths-status.json",
                {
                    "status": "input_unavailable",
                    "reason": "An agreed live interface census is unavailable.",
                },
            )
            return
        native = raw / "snapshot/native"
        p = {**p, "topology": read(native / "spec.json")}
        census = from_native(p, native)
    proof = verify(case / "gray-paths", evidence(p, census, missing))
    write(
        case / "gray-paths-status.json",
        {"status": proof["status"], "typecheck_ns": proof["typecheck_ns"]},
    )
    return proof


def register(root):
    values = {}
    for n in NETWORKS:
        result = clean(root, n)
        if result["status"] != "pass":
            raise ValueError("Clean Gray path proof failed on " + n)
        values[n] = {k: result[k] for k in ("source_sha256", "evidence_sha256")}
    record = {
        "at": datetime.now(timezone.utc).isoformat(),
        "clean_proofs": values,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "The positive reachability clause of RG-013.04. Match all actual Gray link peers and check the original GrayPathWitness conditions on their paths. For a physically disconnected Gray Firewall, Lean also checks that its entire connected component contains no Inner and that no Gray edge enters it from outside.",
    }
    with (root / "gray-connectivity-protocol.json").open("x") as out:
        json.dump(record, out, indent=2)
        out.write("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--clean", choices=NETWORKS)
    parser.add_argument("--trial", type=Path)
    parser.add_argument("--register", action="store_true")
    parser.add_argument("--recheck-restored", action="store_true")
    args = parser.parse_args()
    if args.clean:
        result = clean(args.run, args.clean)
        print(result["status"], result.get("errors", []))
    if args.trial:
        trial(args.run, args.trial)
    if args.register:
        register(args.run)
    if args.recheck_restored:
        for f in sorted((args.run / "trials").glob("*/*/restoration.json")):
            trial(args.run, f.parent)
