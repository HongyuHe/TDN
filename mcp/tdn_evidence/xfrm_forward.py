"""Expose the isolated XFRM forwarding-policy experiment and its raw observations."""

import hashlib
import json
from pathlib import Path

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "cases", "observations", "coverage"]
LEAN_VIEW = "xfrm_forward_policy"
SCOPE = "Seven isolated IPv4 ICMP trials of XFRM forwarding-policy selection with empty SA databases."
SOURCE_SHA256 = "6cc861c3af0b0d054a211ad7163809b263b37e2709253aebcca2782a870cf01d"


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    require(hashlib.sha256((root / "collector.py").read_bytes()).hexdigest() == SOURCE_SHA256,
            "Unknown XFRM experiment collector")
    document = json.loads((root / "observations.json").read_text())
    require(document["schema"] == "tdn-xfrm-forward-policy/v1" and document["error"] is None,
            "Incomplete or unknown XFRM experiment")
    names = document["namespaces"]
    require(len(names) == len(set(names)) == 3, "Invalid experiment namespace inventory")
    records = {row["id"]: row for row in document["records"]}
    require(len(records) == len(document["records"]), "Duplicate XFRM experiment observation")
    expected = {"no_policy", "required_in_only", "required_fwd", "optional_fwd", "nonmatching_fwd",
                "higher_priority_bypass", "lower_priority_bypass"}
    require(len(document["cases"]) == len(expected) and {row["id"] for row in document["cases"]} == expected,
            "Incomplete XFRM experiment case coverage")

    def counters(identifier):
        record = records[identifier]
        require(record["returncode"] == 0 and record["command"] ==
                ["ip", "netns", "exec", names[1], "cat", "/proc/net/xfrm_stat"], "Wrong counter observation")
        return {key: int(value) for key, value in (line.split() for line in record["stdout"].splitlines())}

    cases = []
    for case in document["cases"]:
        probe = records[case["probe"]]
        require(probe["command"] == ["ip", "netns", "exec", names[0], "ping", "-n", "-c", "1", "-W", "1", "10.100.1.2"],
                "Unknown XFRM experiment probe")
        require(probe["returncode"] in {0, 1}, "Probe failed to run")
        policy = records[case["policies"]]
        require(policy["returncode"] == 0 and policy["command"] ==
                ["ip", "netns", "exec", names[1], "ip", "-d", "xfrm", "policy", "list"], "Wrong policy observation")
        require(all(records[identifier]["returncode"] == 0 for identifier in case["installations"]),
                "Policy installation failed")
        before, after = counters(case["before"]), counters(case["after"])
        require(set(before) == set(after), "Counter inventory changed during trial")
        observed = probe["returncode"] == 0
        require(case["observed_forwarding"] == observed, "Stored result differs from probe")
        cases.append(case | {"device": names[1], "observed_forwarding": observed,
                             "matches_expected": observed == case["expected_forwarding"],
                             "counter_deltas": {key: after[key] - before[key] for key in before if after[key] != before[key]}})
    raw = []
    for row in document["records"]:
        command = row["command"]
        device = command[3] if command[:3] == ["ip", "netns", "exec"] else None
        raw.append({"id": row["id"], "device": device, "record": row})
    report = {"devices": [{"id": name, "role": role} for name, role in zip(names, ["source", "gateway", "destination"])],
              "cases": cases, "observations": raw, "coverage": [{"scope": SCOPE, "cases": len(cases)}],
              "scope": [SCOPE, document["scope"]], "manifestSha256": manifest_hash,
              "projectionVersion": "xfrm-forward-policy-v1"}
    return {"runtime_backend": "Linux-network-namespaces", "started_at": document["started_at"],
            "ended_at": document["ended_at"]}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    rows = [row for row in report["observations"] if row["id"] == observation]
    require(len(rows) == 1, "Unknown XFRM experiment observation")
    return rows[0]["record"]["stderr" if stderr else "stdout"]


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
