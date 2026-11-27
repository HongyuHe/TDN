"""Apply the current Lean suite to an archived scaling study in a separate directory."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from scale.catalog import CASES
from scale.profiles import NETWORKS
from scale.review import lean_verdict
from scale.verification import read, verify
from snapshot_inputs import put


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replay(source, output, workers=3):
    if output.exists() or output.resolve().is_relative_to(source.resolve()):
        raise ValueError("Choose a new directory outside the archived study")
    (output / "controls").mkdir(parents=True)
    os.environ.setdefault("TDN_BENCHMARK_LEAN_TIMEOUT", "1200")

    def run(job):
        name, key = job
        if key == "control":
            original = source / "raw/controls" / name
            target = output / "controls" / (name + "-frozen")
            registered = (
                source / "verified-tdn/controls" / (name + "-approved-paths.json")
            )
            put(output / "controls" / registered.name, read(registered))
            bundle = None
        else:
            cell = source / "measurements" / name / key
            original = cell / "capture"
            target = output / "measurements" / name / key / "tdn"
            receipt = read(cell / "cell.json")
            manifest = read(cell / "reader-input.json")
            bundle = manifest["bundle"]
            if (
                not receipt["observed"]
                or receipt["bundle"] != bundle
                or digest(source / "raw" / bundle) + ".json.gz" != bundle
            ):
                raise ValueError("Invalid original capture registration")
            for file in (
                "native/snapshot.json",
                "native/spec.json",
                "processing/observations.json",
            ):
                if (
                    digest(original / "snapshot" / file)
                    != manifest["source_hashes"][file]
                ):
                    raise ValueError("Snapshot differs from the blind reader input")
        checks = verify(
            output, name, original / "snapshot", target, control=key == "control"
        )
        if key == "control":
            rejected = []
            errors = {
                k: v["status"] for k, v in checks.items() if v["status"] != "pass"
            }
        else:
            clean = read(output / "controls" / (name + "-frozen") / "verification.json")
            _, failures, errors = lean_verdict(checks, clean)
            rejected = list(failures)
        print(name, key, "rejected", rejected, "errors", errors, flush=True)
        return dict(
            network=name,
            case=key,
            bundle=bundle,
            rejected=rejected,
            errors=errors,
            verification_sha256=digest(target / "verification.json"),
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        controls = list(pool.map(run, [(n, "control") for n in NETWORKS]))
        put(output / "control-results.json", controls)
        if any(x["rejected"] or x["errors"] for x in controls):
            raise ValueError("A healthy control did not pass. See control-results.json")
        results = list(pool.map(run, [(n, c.key) for c in CASES for n in NETWORKS]))
    put(output / "results.json", results)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--workers", type=int, choices=range(1, 7), default=3)
    a = p.parse_args()
    replay(a.source.resolve(), a.output.resolve(), a.workers)
