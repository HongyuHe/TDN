"""Index the captured Gray ACLs and emit checked allow-rule and deny-atom witnesses."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from route_certificates import paths, radix, tree


def ordered(entries):
    items = sorted(entries.items())
    if not items:
        return "empty"
    middle = len(items) // 2
    key, value = items[middle]
    return {"node": {"key": key, "value": value,
                     "left": ordered(dict(items[:middle])), "right": ordered(dict(items[middle + 1:]))}}


def make_table(rules):
    split = max((i + 1 for i, rule in enumerate(rules) if rule["verdict"] != "allow"), default=0)
    earlier, allowed = rules[:split], rules[split:]
    rejected = []
    for rule in earlier:
        if rule["verdict"] == "allow":
            rejected.append(0)
        else:
            atom_index = next((i for i, atom in enumerate(rule["atoms"])
                               if isinstance(atom, dict) and "networkBytesRange" in atom), None)
            if atom_index is None:
                raise ValueError("Unsupported earlier deny rule; supply an appropriate exclusion witness")
            rejected.append(atom_index)
    entries = {}
    for rule, path in zip(allowed, paths(len(allowed))):
        source = next(atom["sourceRange"] for atom in rule["atoms"]
                      if isinstance(atom, dict) and "sourceRange" in atom)
        if source["low"] != source["high"]:
            raise ValueError("Gray witness keys require an exact source address")
        protocol = next(atom["protocol"]["name"] for atom in rule["atoms"]
                        if isinstance(atom, dict) and "protocol" in atom)
        if protocol == "esp":
            kind = 0
        elif "ipsecUDPFramingWithOptions" in rule["atoms"]:
            kind = 1
        elif "ipsecUDPReplyFramingWithOptions" in rule["atoms"]:
            kind = 2
        else:
            raise ValueError("Unsupported Gray allow-rule form")
        key = source["low"] * 3 + kind
        if key in entries:
            raise ValueError("Ambiguous Gray witness key; extend the key before indexing these rules")
        entries[key] = {"ruleIndex": path, "rejectedAtoms": rejected}
    return {"index": {"earlierRules": earlier, "allowed": tree(allowed)}, "witnesses": ordered(entries)}


def generate(source):
    records = json.loads(source.read_text())
    gray = {d["id"] for d in records["components"] if d["kind"] == "grayFirewall"}
    interfaces = {i["id"] for i in records["interfaces"] if i["device"] in gray}
    unique, bindings, tables = {}, {}, []
    for policy in records["policies"]:
        if policy["interface"] not in interfaces or policy["hook"] != "forward":
            continue
        rules = json.dumps(policy["rules"], sort_keys=True)
        if rules not in unique:
            unique[rules] = len(tables)
            tables.append(make_table(policy["rules"]))
        iface = records["ifaceNames"].index(policy["interface"])
        direction = 0 if policy["direction"] == "inbound" else 1
        key = 2 * iface + direction
        if key in bindings:
            raise ValueError("Duplicate interface/direction FORWARD policy")
        bindings[key] = unique[rules]
    table_paths = paths(len(tables))
    return {"tables": tree(tables), "bindings": radix({k: table_paths[v] for k, v in bindings.items()}),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = json.dumps(generate(args.source), separators=(",", ":")) + "\n"
    if args.check:
        if args.output.read_text() != result:
            raise SystemExit("ACL certificates are stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result)


if __name__ == "__main__":
    main()
