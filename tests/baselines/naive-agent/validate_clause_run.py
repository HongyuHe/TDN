"""Verify that each scored observation was made while its one live change was present."""

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from freeze_protocol import ROOT, digest, manifest
from observe_controls import HERE, NETWORKS
from run_series import plan
from score_trials import METHODS, read, records, summarize, type_verdict


def moment(text):
    return datetime.fromisoformat(text)


def within(start, end, interval, label):
    if (
        interval[0] < start
        or interval[1] > end + timedelta(seconds=1)
        or interval[1] < interval[0]
    ):
        raise ValueError(f"{label} ran outside its held network change")


def validate(root, require_complete):
    data = records(root)
    expected = set(plan())
    measured = {(r["type"], r["network"]) for r in data}
    if measured - expected:
        raise ValueError("An unregistered case was scored")
    missing = sorted(expected - measured)
    if require_complete and missing:
        raise ValueError(f"{len(missing)} registered trials still need scores")
    intervals = []
    detector_runs = Counter()
    snapshots = Counter()
    for row in data:
        folder = (root / row["record"]).parent
        label = row["type"] + "/" + row["network"]
        events = [
            json.loads(line)
            for line in (folder / "events.jsonl").read_text().splitlines()
        ]

        def time_of(name):
            matches = [moment(e["at"]) for e in events if e["event"] == name]
            if len(matches) != 1:
                raise ValueError(f"{label} has {len(matches)} events named {name}")
            return matches[0]

        edited = time_of("change_requested")
        verified = time_of("single_fault_observed")
        restored = time_of("restoration_verified")
        if not edited <= verified < restored:
            raise ValueError("Invalid measurement order on " + label)
        intervals.append((edited, restored, label))
        for m in ("astra", "sol"):
            audit = read(folder / m / "execution.json")
            start = moment(audit["started_at"])
            within(
                verified,
                restored,
                (start, start + timedelta(seconds=audit["duration_seconds"])),
                m + " " + label,
            )
            detector_runs[m] += 1
        raw = row["capture"]
        if raw is None:
            raise ValueError("No live capture record for " + label)
        began = moment(raw["started_at"])
        within(
            verified,
            restored,
            (began, began + timedelta(seconds=raw["seconds"])),
            "capture " + label,
        )
        snapshots["converged" if raw["converged"] else "full_capture_incomplete"] += 1
        if not raw["converged"]:
            supplemental = folder / "interface-stability.json"
            if supplemental.is_file():
                st = read(supplemental)
                if st["first"] != st["last"]:
                    raise ValueError("The live placement data changed during " + label)
                snapshots["stable_interface_census"] += 1
        if row["methods"]["tdn"]["verdict"] == "hit" and not any(
            v == "rejected" for v in row["methods"]["tdn"]["proof_results"].values()
        ):
            raise ValueError("No actual Lean rejection for " + label)
    intervals.sort()
    for previous, following in zip(intervals, intervals[1:]):
        if previous[1] > following[0]:
            raise ValueError(
                "Overlapping changes: " + previous[2] + " and " + following[2]
            )
    scoring = summarize(root)
    for group in scoring["types"].values():
        for m in METHODS:
            if group["verdicts"][m] != type_verdict(
                [group["cells"][m][n] for n in NETWORKS]
            ):
                raise ValueError("Four-network score mismatch")
    if require_complete:
        frozen = read(root / "protocol.json")
        current = manifest(root)
        for k in current.keys() - {"captured_at"}:
            if frozen[k] != current[k]:
                raise ValueError("Changed frozen comparison input: " + k)
        delivery = read(root / "delivery-protocol.json")
        for base, hashes in (
            (ROOT, delivery["sources_sha256"]),
            (root, delivery["control_files_sha256"]),
        ):
            for name, expected in hashes.items():
                if digest(base / name) != expected:
                    raise ValueError("Changed delivery proof input: " + name)
        gray = read(root / "gray-connectivity-protocol.json")
        gray_sources = {
            "GrayConnectivityChecks.lean": gray["source_sha256"],
            "gray_connectivity.py": gray["collector_sha256"],
        }
        for name, expected in gray_sources.items():
            if digest(HERE / name) != expected:
                raise ValueError("Changed Gray connectivity proof input: " + name)
    return {
        "at": datetime.now(timezone.utc).isoformat(),
        "original_networks": list(NETWORKS),
        "registered_applicable_trials": len(expected),
        "verified_disjoint_live_trials": len(intervals),
        "unreviewed_registered_cases": missing,
        "detector_runs": dict(detector_runs),
        "captures": dict(snapshots),
        "included_methods": list(METHODS),
        "verified": "Scored fault intervals were pairwise disjoint. Every included Detector run and live capture fell within its independently verified fault interval.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--complete", action="store_true")
    args = parser.parse_args()
    result = validate(args.run, args.complete)
    if args.complete:
        (args.run / "validation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        result["verified_disjoint_live_trials"],
        "verified live trials;",
        len(result["unreviewed_registered_cases"]),
        "outstanding",
    )
