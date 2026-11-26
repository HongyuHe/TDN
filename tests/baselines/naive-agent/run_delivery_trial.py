"""Run one isolated forwarding or local permit-completeness trial."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import time

from blind_audit import MODELS, run
from attachment_view import check as check_attachments, from_native
from capture_stable import capture_stable
from delivery_lab import change, counter, probe, selection
from delivery_paths import check_trial as check_paths
from full_suite import suite
from measure import typecheck
from mode_lab import evidence, profile, snapshot
from restore_health import verify as verify_health
from observe_controls import HERE, NETWORKS
from run_mode_trial import event, write


def delivered(rows):
    return {(r["source"], r["destination"]) for r in rows if r["delivered"]}


def execute(root, name, family):
    if family not in {"inner-empty-ipv4-header", "firewall-local-empty-udp", "outer-eligible-deny"}:
        raise ValueError("Unregistered forwarding case")
    declared = profile(name)
    selected = selection(declared, family)
    trial = root / "trials" / family / name
    trial.mkdir(parents=True, exist_ok=False)
    before = probe(declared, selected)
    write(trial / "before.json", before)
    header_only = family in ("inner-empty-ipv4-header", "firewall-local-empty-udp")
    if header_only and (len(before) != 1 or before[0]["accepted_by_local_ip"]):
        raise ValueError("The clean gateway must drop the observed header")
    if not header_only and len(delivered(before)) != len(before):
        raise ValueError("A required Red pair already fails")
    clean = json.loads(
        (root / "controls" / (name + "-frozen") / "summary.json").read_text()
    )
    if any(v["status"] != "pass" for v in clean.values()):
        raise ValueError("A fixed clean proof already failed")
    nonce = secrets.token_hex(6)
    write(
        trial / "lease.json",
        {
            "nonce": nonce,
            "network": name,
            "device": selected["device"],
            "fault": family,
        },
    )
    event(trial, "change_requested")
    result = change(selected, "edit", nonce)
    try:
        write(trial / "change.json", result)
        first = counter(selected)
        observed = probe(declared, selected)
        last = counter(selected)
        write(
            trial / "independent-evidence.json",
            {
                "probe": observed,
                "counter_before": first,
                "counter_after": last,
                "rule": selected,
            },
        )
        if header_only:
            valid = (
                len(observed) == 1
                and observed[0]["accepted_by_local_ip"]
                and last["packets"] == first["packets"] + 1
            )
        else:
            valid = last["packets"] > first["packets"] and delivered(
                before
            ) != delivered(observed)
        if not valid:
            event(trial, "fault_not_established")
            return
        event(trial, "single_fault_observed", device=selected["device"])
        with ThreadPoolExecutor(max_workers=4) as pool:
            audits = {m: pool.submit(run, m, trial / m) for m in MODELS}
            cap = pool.submit(
                capture_stable, declared, root / "raw" / "trials" / family / name
            )
            modes = snapshot(declared)
            write(trial / "mode-observations.json", modes)
            checks = {
                "example : ConfiguredTunnelModes " + role + "Modes := by native_decide"
                for role in ("inner", "outer")
            }
            measured = typecheck(
                HERE / "ModeChecks.lean", trial / "lean", evidence(modes), checks
            )
            event(trial, "mode_checks", status=measured["status"])
            ready = cap.result()
            if ready["converged"]:
                folder = root / "raw" / "trials" / family / name / "snapshot"
                allproofs = suite(
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
                    "tdn_finished",
                    status={k: v["status"] for k, v in allproofs.items()},
                )
            else:
                event(trial, "snapshot_unsettled")
            for m, f in audits.items():
                a = f.result()
                event(trial, "detector_finished", model=m, status=a["status"])
        counter(selected)
    finally:
        r = change(selected, "restore", nonce)
        write(trial / "restoration.json", r)
        health = verify_health(declared)
        write(trial / "restored-health.json", health)
        recovered = False
        for _ in range(4):
            restored = probe(declared, selected)
            recovered = (
                (len(restored) == 1 and not restored[0]["accepted_by_local_ip"])
                if header_only
                else delivered(restored) == delivered(before)
            )
            if recovered:
                break
            time.sleep(3)
        write(trial / "delivery-restored.json", restored)
        if r["restored"] != result["before"] or not recovered:
            raise ValueError("Restored filters or Red delivery differ from the control")
        if not health["ready"]:
            raise ValueError("Tunnel or Red-delivery restoration failed")
        event(trial, "restoration_verified")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run", type=Path)
    p.add_argument("network", choices=NETWORKS)
    p.add_argument(
        "family",
        choices=[
            "outer-eligible-deny",
            "inner-empty-ipv4-header",
            "firewall-local-empty-udp",
        ],
    )
    a = p.parse_args()
    execute(a.run.resolve(), a.network, a.family)
