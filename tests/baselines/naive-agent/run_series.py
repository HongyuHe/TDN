"""Run the active networks in sequence and pause for adjudication after each restoration."""

import argparse
import fcntl
import json
from pathlib import Path
import subprocess
import sys
import time

from observe_controls import HERE, NETWORKS
from score_trials import KNOWN_TYPES, records


ORDER = (
    "inner-mode",
    "outer-mode",
    "shared-inner-gateway",
    "inner-empty-ipv4-header",
    "firewall-local-empty-udp",
    "outer-eligible-deny",
    "gray-cross-level-forward",
    "firewall-inside-disconnected",
    "firewall-outside-disconnected",
    "gray-cross-level-path",
    "inner-peer-loopback",
)


def plan():
    scope = json.loads((HERE / "clause_scope.json").read_text())
    if set(ORDER) != set(KNOWN_TYPES) or len(ORDER) != len(KNOWN_TYPES):
        raise ValueError(
            "The sequence must include every registered fault type exactly once"
        )
    for family in ORDER:
        for network in NETWORKS:
            ids = KNOWN_TYPES[family]["clause_ids"]
            if any(
                scope[c]["scope"][network] in ("applicable", "partly applicable")
                for c in ids
            ):
                yield family, network


def run(root):
    from cohort import require_current_run
    require_current_run(root)
    if not (root / "protocol.json").is_file():
        raise ValueError("Register all three clean controls before starting the series")
    with (root / ".series.lock").open("a+") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        completed = {(r["type"], r["network"]) for r in records(root)}
        for family, network in plan():
            if (family, network) in completed:
                continue
            path = root / "trials" / family / network
            if not path.exists():
                print(f"Starting {family} on {network}", flush=True)
                subprocess.run(
                    [
                        sys.executable,
                        str(HERE / "run_case.py"),
                        str(root),
                        network,
                        family,
                    ],
                    check=True,
                )
            print(f"Waiting for the review of {path}", flush=True)
            while not (path / "adjudication.json").is_file():
                log = path / "events.jsonl"
                if log.is_file():
                    events = {
                        json.loads(line)["event"]
                        for line in log.read_text().splitlines()
                        if line
                    }
                    if (
                        "restoration_verified" in events
                        and "single_fault_observed" not in events
                    ):
                        raise RuntimeError(
                            f"The original state was restored before a fault could be established: {path}"
                        )
                time.sleep(2)
            completed = {(r["type"], r["network"]) for r in records(root)}
            if (family, network) not in completed:
                raise ValueError(f"No validated score for {path}")
        print(f"{len(completed)} applicable registered trials reviewed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        for family, network in plan():
            print(f"{network}  {family}")
    else:
        run(args.run.resolve())
