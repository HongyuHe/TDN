"""Capture once per cell. Score two independent, offline readers of the same captured state."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import time
from threading import Event

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from blind_audit import PROMPT
from capture_stable import capture_stable
from restore_health import verify as health
from run_snapshot_audits import TIMEOUT, audit_saved
from scale.catalog import BY_NAME, CASES, CHANGES
from scale.live import held, install_policy
from scale.profiles import NETWORKS, inventory, profile
from scale.verification import connections, verify
from snapshot_inputs import PDF, digest, publish_capture, put


def read(p):
    return json.loads(p.read_bytes())


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def revision():
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=HERE, text=True
    ).strip()


def initialize(root):
    if root == HERE or root == Path("/"):
        raise ValueError("Choose a results directory")
    root.mkdir(parents=True, exist_ok=True)
    os.environ["TDN_BENCHMARK_LEAN_TIMEOUT"] = "1200"
    registry = {
        "revision": revision(),
        "lean_process_timeout_seconds": 1200,
        "pdf_sha256": digest(PDF.read_bytes()),
        "detector": "gpt-6-astra",
        "reasoning": "high",
        "prompt": PROMPT,
        "timeout_seconds": TIMEOUT,
        "networks": {name: inventory(name) for name in NETWORKS},
        "cases": [{**vars(c), "change": CHANGES[c.key]} for c in CASES],
        "scope": "one fault per network, one anonymous snapshot per independent session",
        "credit": "A substantiated description of the planted violation or its direct effect counts. A nearby but different finding does not. Only observed, restored cases enter detection denominators.",
        "time": "Astra wall time. Lean elapsed time inside each proof file after its data have been imported. Sum each file's interval.",
    }
    put(root / "protocol.json", registry)
    if not (root / "started-at.json").exists():
        put(root / "started-at.json", {"utc": timestamp()})


def archive(path):
    if not path.exists():
        return
    target = path.parent / "attempts" / (path.name + "-" + str(time.time_ns()))
    target.parent.mkdir(exist_ok=True)
    path.rename(target)


def stable(p, dest):
    if (dest / "capture.json").exists() and read(dest / "capture.json")["converged"]:
        return
    archive(dest)
    result = capture_stable(p, dest, attempts=4)
    if not result["converged"]:
        raise RuntimeError("No stable capture for " + p["network"])


def clean(root, n):
    p = profile(n)
    dest = root / "raw/controls" / n
    folder = root / "controls" / (n + "-frozen")
    (root / "controls").mkdir(parents=True, exist_ok=True)
    if not (dest / "capture.json").exists():
        saved = install_policy(p)
        put(root / "controls" / (n + "-designations.json"), saved)
        state = health(p)
        path = root / "preflight" / n / (str(time.time_ns()) + ".json")
        put(path, state)
        if not state["ready"]:
            raise ValueError("Incomplete cross-site health on " + n)
    stable(p, dest)
    if not (folder / "verification.json").exists():
        archive(folder)
        verify(root, n, dest / "snapshot", folder, control=True)
    results = read(folder / "verification.json")
    errs = {k: v for k, v in results.items() if v["status"] != "pass"}
    if errs:
        raise ValueError(
            n
            + " clean control failed: "
            + str([(k, v.get("message", v["status"])) for k, v in errs.items()])[:650]
        )
    print(n, "passing clean obligations", len(results), flush=True)


def capture_one(root, n, key):
    trial = root / "measurements" / n / key
    p = profile(n)
    if (trial / "cell.json").exists():
        return read(trial / "cell.json")
    archive(trial)
    trial.mkdir(parents=True)
    start = timestamp()
    with held(p, key, trial / "operator") as witness:
        dest = trial / "capture"
        stable(p, dest)
        saved = dest / "snapshot"
        modes = connections(saved / "native")
        blob, signatures = publish_capture(
            saved, root / "raw", modes, intent=p["topology"]
        )
        put(trial / "reader-input.json", {"bundle": blob, "source_hashes": signatures})
    after = health(p)
    put(trial / "post-health.json", after)
    if not after["ready"]:
        raise RuntimeError("Post-trial Red delivery did not recover on " + n)
    result = {
        "network": n,
        "case": key,
        "start": start,
        "restored_at": timestamp(),
        "observed": witness["observed"],
        "bundle": blob,
        "capture_seconds": read(dest / "capture.json")["seconds"],
    }
    put(trial / "cell.json", result)
    print(n, key, "observed" if result["observed"] else "unexercised", flush=True)
    return result


def capture_network(root, n, order=None):
    lock = root / (n + ".lock")
    with lock.open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        control = read(root / "controls" / (n + "-frozen") / "verification.json")
        if not control or any(row["status"] != "pass" for row in control.values()):
            raise ValueError("The complete control must pass before applying a fault")
        for key in order or [c.key for c in CASES]:
            capture_one(root, n, key)


def offline(root, n, key, method):
    cell = root / "measurements" / n / key
    record = read(cell / "cell.json")
    if method == "astra":
        result = audit_saved(
            key + "/" + n, "astra", {"network": record["bundle"]}, root
        )
    else:
        target = cell / "tdn"
        if not (target / "verification.json").is_file():
            archive(target)
            verify(root, n, cell / "capture/snapshot", target)
        result = {k: v["status"] for k, v in read(target / "verification.json").items()}
    return n, key, result


def stream(root, method, workers, stopped=None):
    jobs = {(n, c.key) for n in NETWORKS for c in CASES}
    pending = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        while jobs or pending:
            if stopped is not None and stopped.is_set():
                return
            for f in list(pending):
                if f.done():
                    n, key = pending.pop(f)
                    r = f.result()
                    print(method, r, flush=True)
                    if method == "astra" and r[2] != "completed":
                        with (root / "detector-interruptions.jsonl").open("a") as out:
                            out.write(
                                json.dumps(
                                    {
                                        "time": timestamp(),
                                        "network": n,
                                        "case": key,
                                        "status": r[2],
                                    }
                                )
                                + "\n"
                            )
            available = sorted(
                (n, key)
                for n, key in jobs
                if (root / "measurements" / n / key / "cell.json").exists()
            )
            for n, key in available[: max(0, workers - len(pending))]:
                jobs.remove((n, key))
                pending[pool.submit(offline, root, n, key, method)] = (n, key)
            if jobs or pending:
                time.sleep(2)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument(
        "action", choices=("init", "controls", "capture", "astra", "tdn", "one", "all")
    )
    cli.add_argument("results", type=Path)
    cli.add_argument("--network", choices=NETWORKS)
    cli.add_argument("--case", choices=BY_NAME)
    cli.add_argument("--method", choices=["astra", "tdn"])
    cli.add_argument("--workers", type=int, default=4)
    a = cli.parse_args()
    root = a.results.resolve()
    if not 1 <= a.workers <= 8:
        cli.error("workers must be between one and eight")
    initialize(root)
    if a.action == "init":
        return
    ns = [a.network] if a.network else list(NETWORKS)
    if a.action in ("controls", "all"):
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(lambda n: clean(root, n), ns))
        if a.action == "controls":
            return
    if a.action == "one":
        if not all([a.network, a.case, a.method]):
            cli.error("one requires network, case and method")
        print(offline(root, a.network, a.case, a.method))
        return
    if a.action in ("astra", "tdn"):
        stream(root, a.action, a.workers)
        return
    if a.action == "all" and (a.case or a.network):
        cli.error("all runs the full matrix")
    order = {n: [c.key for c in CASES] for n in ns}
    for i, n in enumerate(ns):
        random.Random(408 + i).shuffle(order[n])
    if a.action == "all":
        stopped = Event()
        with ThreadPoolExecutor(max_workers=5) as pool:
            runs = [pool.submit(capture_network, root, n, order[n]) for n in ns]
            runs.extend(
                [
                    pool.submit(stream, root, "astra", a.workers, stopped),
                    pool.submit(stream, root, "tdn", 2, stopped),
                ]
            )
            try:
                for f in as_completed(runs):
                    f.result()
            finally:
                stopped.set()
    else:
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(
                pool.map(
                    lambda n: capture_network(
                        root, n, [a.case] if a.case else order[n]
                    ),
                    ns,
                )
            )


if __name__ == "__main__":
    main()
