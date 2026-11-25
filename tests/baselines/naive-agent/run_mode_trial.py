"""Run one live trial with fresh auditors, fixed Lean obligations, and monitored cleanup."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
from datetime import datetime, timezone

from blind_audit import MODELS, run
from capture_stable import capture_stable
from attachment_view import check as check_attachments, from_native
from full_suite import suite
from measure import typecheck
from mode_lab import edit, evidence, profile, snapshot
from delivery_paths import check_trial as check_paths
import peer_lab
from restore_health import verify as verify_health
from observe_controls import HERE, NETWORKS


def write(path, value):
    with path.open("x") as target:
        json.dump(value, target, indent=2)
        target.write("\n")


def event(directory, name, **fields):
    with (directory / "events.jsonl").open("a") as target:
        target.write(
            json.dumps(
                {"at": datetime.now(timezone.utc).isoformat(), "event": name, **fields}
            )
            + "\n"
        )


def captured_modes(rows):
    return {r["device"]: r["mode"] for r in rows}


def execute(root, name, layer):
    peer_case = layer == "inner-peer"
    family = "inner-peer-loopback" if peer_case else layer + "-mode"
    trial = root / "trials" / family / name
    trial.mkdir(parents=True, exist_ok=False)
    declared = profile(name)
    target_layer = "inner" if peer_case else layer
    device = next(
        d["id"]
        for d in declared["topology"]["devices"]
        if d["role"] == target_layer and d["id"].endswith("_A1")
    )
    observed_field = peer_lab.loaded_peers if peer_case else captured_modes

    def change_connection(action, nonce):
        return (
            peer_lab.change(declared, action, nonce)
            if peer_case
            else edit(declared, device, action, nonce)
        )

    checks = {
        "example : ConfiguredTunnelModes " + role + "Modes := by native_decide"
        for role in ("inner", "outer")
    }
    source = HERE / "ModeChecks.lean"
    clean = json.loads(
        (root / "controls" / (name + "-modes") / "result.json").read_text()
    )
    if (
        clean["status"] != "pass"
        or clean["source_sha256"] != hashlib.sha256(source.read_bytes()).hexdigest()
    ):
        raise ValueError(
            "The exact fixed suite must pass the clean snapshot before this trial"
        )
    before = {n: observed_field(snapshot(profile(n))) for n in NETWORKS}
    for n, rows in before.items():
        control = observed_field(
            json.loads((root / "controls" / (n + ".json")).read_text())
        )
        if rows != control:
            raise ValueError("A control changed on " + n)
    write(trial / "before.json", before)
    if peer_case:
        try:
            renewed = peer_lab.reconnect(declared)
            write(trial / "fresh-peer-control.json", renewed)
        except Exception:
            write(trial / "failed-control-health.json", verify_health(declared))
            raise
    nonce = secrets.token_hex(6)
    write(
        trial / "lease.json",
        {"nonce": nonce, "network": name, "device": device, "fault": family},
    )
    event(trial, "change_requested")
    change = change_connection("edit", nonce)
    try:
        write(trial / "change.json", change)
        if peer_case:
            write(
                trial / "fresh-peer-fault.json",
                peer_lab.reconnect(declared, faulty=True),
            )
        observed = {n: snapshot(profile(n)) for n in NETWORKS}
        write(trial / "snapshot.json", observed)
        diffs = [
            (n, d, old, observed_field(observed[n])[d])
            for n, rows in before.items()
            for d, old in rows.items()
            if observed_field(observed[n])[d] != old
        ]
        expected = (
            (change["original_address"], change["running_address"])
            if peer_case
            else ("TUNNEL", "TRANSPORT")
        )
        if diffs != [(name, device, *expected)]:
            raise ValueError(
                "Expected one independently observed active configuration change"
            )
        event(trial, "single_fault_observed", device=device)
        with ThreadPoolExecutor(max_workers=4) as pool:
            dumped = pool.submit(
                capture_stable, declared, root / "raw" / "trials" / family / name
            )
            audits = {model: pool.submit(run, model, trial / model) for model in MODELS}
            lean = pool.submit(
                typecheck, source, trial / "lean", evidence(observed[name]), checks
            )
            result = lean.result()
            event(trial, "lean_finished", status=result["status"])
            for model, f in audits.items():
                audit = f.result()
                event(trial, "detector_finished", model=model, status=audit["status"])
            capture_result = dumped.result()
            event(
                trial, "full_snapshot_collected", converged=capture_result["converged"]
            )
            if capture_result["converged"]:
                folder = root / "raw" / "trials" / family / name / "snapshot"
                proofs = suite(
                    folder / "native", folder / "processing", trial / "tdn-full"
                )
                check_attachments(
                    declared,
                    from_native(declared, folder / "native"),
                    trial / "attachment-check",
                )
                if (root / "delivery-protocol.json").is_file():
                    check_paths(root, name, trial)
                event(
                    trial,
                    "full_suite_finished",
                    status={k: v["status"] for k, v in proofs.items()},
                )
        after = observed_field(snapshot(declared))
        if after != observed_field(observed[name]):
            raise ValueError("Fault changed while detectors were inspecting it")
    finally:
        restored = change_connection("restore", nonce)
        write(trial / "restoration.json", restored)
        rows = observed_field(snapshot(declared))
        hashes = (
            (restored["restored"], change["original"])
            if peer_case
            else (restored["restored_sha256"], change["previous_sha256"])
        )
        if rows != before[name] or hashes[0] != hashes[1]:
            raise ValueError("Restoration could not be verified")
        health = verify_health(declared)
        write(trial / "restored-health.json", health)
        if not health["ready"]:
            raise ValueError("Tunnel or Red-delivery restoration failed")
        event(trial, "restoration_verified")
    print("Trial records", trial, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("network", choices=NETWORKS)
    parser.add_argument("layer", choices=("inner", "outer", "inner-peer"))
    args = parser.parse_args()
    execute(args.run.resolve(), args.network, args.layer)
