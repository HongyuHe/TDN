"""Inspect every published scaling trial for operator metadata and placement bias."""

import argparse
from difflib import SequenceMatcher
import gzip
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from scale.blinding import canonical_mount, marker_counts
from scale.catalog import CASES, FIREWALL_CHAINS
from scale.panel import ROLES, changed_first_rules, child_names, eligible, first_filter_rules
from scale.profiles import NETWORKS, profile
from scale.verification import read


def filters(snapshot):
    return {
        (c["device_id"], c["chain"]): [r["raw_text"] for r in c["ordered_rules"]]
        for c in snapshot["filters"]
        if c["family"] == 4
    }


def audit(source):
    results = []
    for n in NETWORKS:
        spec = profile(n)["topology"]
        devices = {d["id"]: d for d in spec["devices"]}
        clean = read(source / "raw/controls" / n / "snapshot/native/snapshot.json")
        before = filters(clean)
        opening_rules = first_filter_rules(clean)

        def veths(s):
            return {
                frozenset(row["endpoint_interface_ids"]): int(
                    row["id"].removeprefix("link-")
                )
                for row in s["links"]
                if row["relation"] == "veth"
            }

        clean_links = veths(clean)
        for case in CASES:
            key = case.key
            trial = source / "measurements" / n / key
            receipt = read(trial / "cell.json")
            packed = (source / "raw" / receipt["bundle"]).read_bytes()
            from snapshot_inputs import digest

            if digest(packed) + ".json.gz" != receipt["bundle"]:
                raise ValueError("Changed published capture")
            content = gzip.decompress(packed)
            signals = marker_counts(canonical_mount(content))
            snapshot = read(trial / "capture/snapshot/native/snapshot.json")
            (role,) = [r for r, ids in ROLES.items() if key in ids]
            anchors = set()
            ranks = []
            new_ports = set()
            if key in FIREWALL_CHAINS:
                hook = FIREWALL_CHAINS[key]
                for (d, h), rules in filters(snapshot).items():
                    if devices[d]["role"] != role or hook != h or rules == before[d, h]:
                        continue
                    anchors.add(d)

                    def ports(rows):
                        return {
                            v
                            for rule in rows
                            for group in re.findall(r"--(?:s|d)ports? ([\d,]+)", rule)
                            for v in group.split(",")
                            if int(v) >= 32768
                        }

                    new_ports.update(ports(rules) - ports(before[d, h]))
                    ranks.extend(
                        i + 1
                        for op, _, _, a, b in SequenceMatcher(
                            None, before[d, h], rules, autojunk=False
                        ).get_opcodes()
                        if op != "equal"
                        for i in range(a, b)
                    )
            else:
                change = read(trial / "operator/change.json")
                if change.get("device"):
                    anchors.add(change["device"])
                elif key == "inner-cross-level-auth":
                    baseline = read(
                        source / "raw/controls" / n / "snapshot/enclave-policy.json"
                    )
                    old = {r["red"]: r["record"] for r in baseline}
                    anchors.update(
                        r["attached_inner"]
                        for r in read(trial / "capture/snapshot/enclave-policy.json")
                        if r["record"] != old[r["red"]]
                    )
                elif key == "outer-firewall-alternate-path":
                    declared = {
                        frozenset((e["device"], e["interface"]) for e in row.values())
                        for row in spec["links"]
                    }
                    for link in read(trial / "capture/snapshot/native/spec.json")[
                        "links"
                    ]:
                        if (
                            frozenset(
                                (e["device"], e["interface"]) for e in link.values()
                            )
                            not in declared
                        ):
                            anchors.update(
                                e["device"]
                                for e in link.values()
                                if devices[e["device"]]["role"] == role
                            )
            if not anchors:
                raise ValueError("Missing operator location for " + key)
            faulty_links = veths(snapshot)
            new_ids = [
                v
                for endpoints, v in faulty_links.items()
                if endpoints not in clean_links
            ]
            results.append(
                dict(
                    network=n,
                    case=key,
                    eligible=len(eligible(spec, key)),
                    anchors=sorted(anchors),
                    inventory_positions=[
                        i
                        for i, d in enumerate(spec["devices"], 1)
                        if d["id"] in anchors
                    ],
                    appended_link_ids=sum(
                        v > max(clean_links.values()) for v in new_ids
                    ),
                    new_tunnel_names=sorted(child_names(snapshot) - child_names(clean)),
                    changed_rule_ranks=sorted(ranks),
                    changed_first_rules=[
                        {"device": device, "family": family, "chain": chain}
                        for device, family, chain in changed_first_rules(opening_rules, first_filter_rules(snapshot))
                    ],
                    marker_counts=signals,
                    new_high_ports=sorted(new_ports),
                    new_interface_names=sorted(
                        {i["name"] for i in snapshot["interfaces"]}
                        - {i["name"] for i in clean["interfaces"]}
                    ),
                )
            )
    return results


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    r = audit(a.source)
    with a.output.open("x") as out:
        json.dump(r, out, indent=2)
        out.write("\n")
    print(
        f"{len(r)} trials, {len({x['case'] for x in r})} types, {sum(bool(x['marker_counts']) for x in r)} inputs with marker hits"
    )
