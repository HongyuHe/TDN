"""Trace a refused live firewall import to its two original representations."""

import argparse
import json
from pathlib import Path
import sys

from observe_controls import HERE

sys.path.insert(0, str(HERE.parents[2] / "mcp"))
from tdn_evidence.parsers.native_nft import (
    actual_conditions,
    expected_conditions,
    read_observation,
)


def difference(counter):
    return [
        {
            "field": field,
            "value": value,
            "python_type": type(value).__name__,
            "count": count,
        }
        for (field, value), count in counter.items()
    ]


def inspect(root, case):
    summary = case / "tdn-full/summary.json"
    if not summary.is_file():
        return
    record = json.loads(summary.read_text()).get("headers", {})
    if record.get("message") != "Nft ordered rule conditions differ":
        return
    device = json.loads((case / "change.json").read_text())["device"]
    native = root / "raw/trials" / case.parent.name / case.name / "snapshot/native"
    snapshot = json.loads((native / "snapshot.json").read_text())
    obs = snapshot["observations"]
    identity = next(
        o
        for o in obs
        if o["kind"] == "container-inspect" and o["command"][-1] == device
    )
    pid = str(read_observation(native, identity)["State"]["Pid"])
    kernel_view = next(
        o for o in obs if o["kind"] == "nft-hooks" and o["command"][2] == pid
    )
    kernel_rules = [
        item["rule"]
        for item in read_observation(native, kernel_view)["nftables"]
        if "rule" in item
        and item["rule"]["family"] == "ip"
        and item["rule"]["chain"] == "INPUT"
    ]
    chain = next(
        c
        for c in snapshot["filters"]
        if c["device_id"] == device and c["chain"] == "INPUT" and c["family"] == 4
    )
    if len(kernel_rules) != len(chain["ordered_rules"]):
        raise ValueError("Different rule counts require a separate diagnosis")
    mismatches = []
    for i, (rule, kernel) in enumerate(zip(chain["ordered_rules"], kernel_rules)):
        expected = expected_conditions(rule)
        actual = actual_conditions(kernel["expr"], rule["action"])
        if expected == actual:
            continue
        a = difference(expected - actual)
        b = difference(actual - expected)
        raw_ids = set(rule["observation_ids"])
        mismatches.append(
            {
                "ordinal": i,
                "iptables_line": rule["raw_text"],
                "iptables_source": [o["raw_path"] for o in obs if o["id"] in raw_ids],
                "nft_source": kernel_view["raw_path"],
                "iptables_only": a,
                "nft_only": b,
                "same_protocol_number_in_text_and_numeric_form": len(a) == len(b) == 1
                and a[0]["field"] == b[0]["field"] == "-p"
                and isinstance(a[0]["value"], str)
                and isinstance(b[0]["value"], int)
                and a[0]["value"] == str(b[0]["value"]),
            }
        )
    if mismatches:
        output = case / "tdn-full/translation-diagnostic.json"
        output.write_text(
            json.dumps(
                {
                    "device": device,
                    "scope": "Original ordered IPv4 INPUT rules from the live capture.",
                    "mismatches": mismatches,
                },
                indent=2,
            )
            + "\n"
        )
        return mismatches


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("case", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.run, args.case), indent=2))
