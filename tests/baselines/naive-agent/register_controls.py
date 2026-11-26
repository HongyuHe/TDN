"""Capture a clean replica, verify it with the fixed proof suite, then freeze the three controls."""

import argparse
import hashlib
import time
import json
from pathlib import Path

from architecture_cases import check as check_architecture
from attachment_view import check as check_attachments, live
from capture_stable import capture_stable
from cohort import HERE, NETWORKS, require_current_run, runtime_profile
from delivery_paths import (
    check as check_delivery,
    clean_paths,
    register as register_delivery,
)
from freeze_protocol import manifest
from full_suite import suite
from gray_connectivity import register as register_gray
from measure import typecheck
from mode_lab import snapshot, evidence as mode_evidence
from restore_health import verify
from run_mode_trial import write


def read(path):
    return json.loads(path.read_text())


def register_network(root, network):
    root = require_current_run(root)
    if (root / "protocol.json").exists():
        raise ValueError("Run inputs were already frozen")
    p = runtime_profile(network)
    controls = root / "controls"
    controls.mkdir(parents=True, exist_ok=True)
    raw = root / "raw/controls" / network
    if not (raw / "capture.json").exists():
        health = verify(p)
        if not health["ready"]:
            raise ValueError(f"Required tunnels and Red deliveries failed on {network}")
        census = live(p)
        if not all(e["up"] and e["reciprocal"] for e in census["links"]):
            raise ValueError("Incomplete clean link census")
        for suffix, rows in (
            ("-inventory", census),
            ("-health", health),
            ("", snapshot(p)),
        ):
            path = controls / (network + suffix + ".json")
            if path.is_file():
                raise ValueError(
                    "An earlier partial control exists. Use a fresh run directory"
                )
            write(path, rows)
        capture_stable(p, raw)
    if not read(raw / "capture.json")["converged"]:
        raise ValueError("The clean capture did not converge")
    files = raw / "snapshot"
    frozen = controls / (network + "-frozen")
    if not (frozen / "summary.json").exists():
        suite(files / "native", files / "processing", frozen)
    results = read(frozen / "summary.json")
    source = HERE / "MscArchitectureChecks.lean"
    if (
        results["architecture"].get("source_sha256")
        != hashlib.sha256(source.read_bytes()).hexdigest()
    ):
        archive = root / "control-attempts" / network / str(time.time_ns())
        archive.mkdir(parents=True)
        (frozen / "architecture").rename(archive / "architecture")
        (archive / "summary.json").write_bytes((frozen / "summary.json").read_bytes())
        fresh = check_architecture(files / "native", frozen / "architecture")
        results["architecture"] = {
            k: fresh[k]
            for k in (
                "status",
                "typecheck_ns",
                "source_sha256",
                "evidence_sha256",
                "failed_obligations",
            )
        }
        temporary = frozen / "summary.tmp"
        temporary.write_text(json.dumps(results, indent=2) + "\n")
        temporary.replace(frozen / "summary.json")
    mode_dir = controls / (network + "-modes")
    if not (mode_dir / "result.json").exists():
        source = HERE / "ModeChecks.lean"
        typecheck(
            source,
            mode_dir,
            mode_evidence(read(controls / (network + ".json"))),
            set(source.read_text().splitlines()),
        )
    link_dir = controls / (network + "-attachments")
    if not (link_dir / "result.json").exists():
        check_attachments(p, read(controls / (network + "-inventory.json")), link_dir)
    for name, folder in (("modes", mode_dir), ("attachments", link_dir)):
        results[name] = read(folder / "result.json")
    failed = {k: v["status"] for k, v in results.items() if v["status"] != "pass"}
    if failed:
        raise ValueError(f"Clean proof errors on {network}: {failed}")
    if not (controls / (network + "-approved-paths.json")).exists():
        clean_paths(root, network)
    management = controls / (network + "-management-inputs.json")
    if not management.exists():
        write(management, [])
    path_dir = controls / (network + "-delivery-check")
    path_record = path_dir / "result.json"
    if (
        path_record.exists()
        and read(path_record)["source_sha256"]
        != hashlib.sha256((HERE / "DeliveryPathChecks.lean").read_bytes()).hexdigest()
    ):
        archive = root / "control-attempts" / network / str(time.time_ns())
        archive.parent.mkdir(parents=True, exist_ok=True)
        path_dir.rename(archive)
    if not path_record.exists():
        check_delivery(root, network, frozen / "forwarding/evidence.json", path_dir)
    if read(path_dir / "result.json")["status"] != "pass":
        raise ValueError("Clean delivery proof failed")
    return {key: v["status"] for key, v in results.items()}


def freeze(root):
    require_current_run(root)
    for n in NETWORKS:
        register_network(root, n)
    controls = root / "controls"
    for filename, data in (
        (
            "control-inventory.json",
            {"networks": [read(controls / (n + "-inventory.json")) for n in NETWORKS]},
        ),
        (
            "control-ready.json",
            {"networks": [read(controls / (n + "-health.json")) for n in NETWORKS]},
        ),
    ):
        target = root / filename
        if not target.exists():
            write(target, data)
        elif read(target) != data:
            raise ValueError(f"Control record differs: {filename}")
    if not (root / "delivery-protocol.json").exists():
        register_delivery(root)
    if not (root / "gray-connectivity-protocol.json").exists():
        register_gray(root)
    write(root / "protocol.json", manifest(root))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("run", type=Path)
    group = cli.add_mutually_exclusive_group(required=True)
    group.add_argument("--network", choices=NETWORKS)
    group.add_argument("--freeze", action="store_true")
    args = cli.parse_args()
    if args.freeze:
        freeze(args.run.resolve())
    else:
        print(
            args.network, register_network(args.run.resolve(), args.network), flush=True
        )
