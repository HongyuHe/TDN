"""Generate untrusted route witnesses for Lean's indexed certificate checker."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def tree(values):
    if not values:
        return "empty"
    if len(values) == 1:
        return {"leaf": {"value": values[0]}}
    middle = len(values) // 2
    return {"branch": {"left": tree(values[:middle]), "right": tree(values[middle:])}}


def paths(size, prefix=()):
    if not size:
        return []
    if size == 1:
        return [list(prefix)]
    middle = size // 2
    return paths(middle, prefix + (False,)) + paths(size - middle, prefix + (True,))


def radix(entries):
    if not entries:
        return "empty"
    return {"node": {
        "value": entries.get(0),
        "even": radix({k // 2: v for k, v in entries.items() if k and k % 2 == 0}),
        "odd": radix({k // 2: v for k, v in entries.items() if k % 2}),
    }}


def rank(route):
    return route["tablePriority"], -route["prefixLength"], route["metric"]


def make_certificate(routes, destination):
    positions = paths(len(routes))
    matching = [i for i, r in enumerate(routes)
                if r["destPrefixLow"] <= destination <= r["destPrefixHigh"]]
    winners = {}
    for i in matching:
        ingress = routes[i]["ingress"]
        if ingress not in winners or rank(routes[i]) < rank(routes[winners[ingress]]):
            winners[ingress] = i
    retained = [i for i in matching if rank(routes[i]) == rank(routes[winners[routes[i]["ingress"]]])]
    selected_paths = dict(zip(retained, paths(len(retained))))
    return {
        "destination": destination,
        "winners": radix({ingress: positions[i] for ingress, i in winners.items()}),
        "retained": tree([routes[i] for i in retained]),
        "coverage": tree([selected_paths.get(i, []) for i in range(len(routes))]),
        "origins": tree([positions[i] for i in retained]),
    }


def generate(source):
    records = json.loads(source.read_text())
    addresses = sorted({pair["endpoints"][field] for pair in records["pairs"]
                        for field in ("sourceAddress", "destinationAddress")})
    return {
        "routes": tree(records["routes"]),
        "certificates": [make_certificate(records["routes"], address) for address in addresses],
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = json.dumps(generate(args.source), separators=(",", ":")) + "\n"
    if args.check:
        if args.output.read_text() != result:
            raise SystemExit("route certificates are stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result)


if __name__ == "__main__":
    main()
