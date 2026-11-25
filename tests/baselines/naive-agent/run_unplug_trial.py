"""Run one physical placement trial without creating an alternative forwarding path."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import time

from attachment_view import attachments, check, live
from blind_audit import MODELS, run
from capture_stable import capture_stable
from delivery_lab import ping
from delivery_paths import check_trial as check_paths
from full_suite import suite
from gray_connectivity import evidence as gray_evidence, trial as gray_check
from measure import typecheck
from mode_lab import evidence, profile, snapshot
from restore_health import verify as verify_health
from observe_controls import HERE, NETWORKS
from run_mode_trial import event, write
from unplug_lab import change, target


def interface_digest(observations):
    records = {
        d["device"]: sorted(d["interfaces"], key=lambda i: i["ifname"])
        for d in observations["devices"]
    }
    return hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def execute(root, name, side="inside"):
    if side not in ("inside", "outside", "gray-inner-links"):
        raise ValueError(
            "Select the inside or the outside of the designated Outer Firewall"
        )
    p = profile(name)
    gray = side == "gray-inner-links"
    family = "gray-firewall-detached" if gray else f"firewall-{side}-disconnected"
    trial = root / "trials" / family / name
    trial.mkdir(parents=True, exist_ok=False)
    dev = target(p, gray)
    nonce = secrets.token_hex(6)
    before = live(p)
    natural = attachments(p, before)
    write(trial / "before.json", before)
    if check(p, before, trial / "clean-attachments")["status"] != "pass":
        raise ValueError("Clean public attachment proof failed")
    write(
        trial / "lease.json",
        {
            "nonce": nonce,
            "network": name,
            "device": dev,
            "fault": family,
        },
    )
    event(trial, "change_requested")
    original = change(p, "edit", nonce, side)
    try:
        write(trial / "change.json", original)
        observed = live(p)
        write(trial / "snapshot.json", observed)
        new = attachments(p, observed)
        if gray:
            if new != natural or gray_evidence(p, before)["regions"]:
                raise ValueError("The original Gray or Black connections differ")
            observed_gray = gray_evidence(
                p, observed, {(dev, i) for i in original["ports"]}
            )
            if [region["firewall"] for region in observed_gray["regions"]] != [dev]:
                raise ValueError(
                    "The designated Gray Firewall must uniquely lose its connection to every Inner"
                )
            write(trial / "gray-links-observed.json", observed_gray)
        else:
            other = "outside" if side == "inside" else "inside"
            owner = 1 if side == "inside" else 0
            missing = set(tuple(a) for a in natural[side]) - set(
                tuple(a) for a in new[side]
            )
            if (
                len(missing) != 1
                or next(iter(missing))[owner] != dev
                or len(new[side]) != len(natural[side]) - 1
                or new[other] != natural[other]
            ):
                raise ValueError("Designated Outer lost a different attachment")
        event(trial, "single_fault_observed", device=dev)
        with ThreadPoolExecutor(max_workers=4) as pool:
            audits = {m: pool.submit(run, m, trial / m) for m in MODELS}
            saved = pool.submit(
                capture_stable,
                p,
                root / "raw" / "trials" / family / name,
            )
            proof = check(p, observed, trial / "attachment-check")
            event(trial, "attachment_checked", status=proof["status"])
            if (root / "gray-connectivity-protocol.json").is_file():
                gray_check(root, trial)
            raw = snapshot(p)
            write(trial / "mode-observations.json", raw)
            checks = {
                "example : ConfiguredTunnelModes " + role + "Modes := by native_decide"
                for role in ("inner", "outer")
            }
            typecheck(HERE / "ModeChecks.lean", trial / "lean", evidence(raw), checks)
            result = saved.result()
            if result["converged"]:
                folder = root / "raw" / "trials" / family / name / "snapshot"
                suite(folder / "native", folder / "processing", trial / "tdn-full")
                if (root / "delivery-protocol.json").is_file():
                    check_paths(root, name, trial)
            else:
                event(trial, "full_collector_incomplete")
            for m, f in audits.items():
                row = f.result()
                event(trial, "detector_finished", model=m, status=row["status"])
        last = live(p)
        write(trial / "interfaces-at-end.json", last)
        stability = {
            "first": interface_digest(observed),
            "last": interface_digest(last),
            "devices": len(last["devices"]),
            "full_native_capture_converged": result["converged"],
            "scope": "Complete live interface census for the placement proof. Both reads occurred while the same interface was disconnected.",
        }
        write(trial / "interface-stability.json", stability)
        if stability["first"] != stability["last"] or attachments(p, last) != new:
            raise ValueError("Interface observations changed while the fault was held")
        if (
            gray
            and gray_evidence(p, last, {(dev, i) for i in original["ports"]})
            != observed_gray
        ):
            raise ValueError("The disconnected Gray component changed during the trial")
        event(trial, "attachment_snapshot_stable")
    finally:
        restored = change(p, "restore", nonce, side)
        write(trial / "restoration.json", restored)
        if (
            restored["restored"] != original["original"]
            or restored["ospf_routes_after"] != original["ospf_routes_before"]
        ):
            raise ValueError("Interface restoration changed attributes")
        health = verify_health(p)
        write(trial / "restored-health.json", health)
        for _ in range(9):
            observed_again = live(p)
            if (
                attachments(p, observed_again) == natural
                and (
                    not gray
                    or gray_evidence(p, observed_again) == gray_evidence(p, before)
                )
                and all(x["delivered"] for x in ping(p))
            ):
                break
            time.sleep(3)
        else:
            raise ValueError(
                "Original attachments or intended Red delivery have not recovered"
            )
        if not health["ready"]:
            raise ValueError("Tunnel or Red-delivery restoration failed")
        event(trial, "restoration_verified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("network", choices=NETWORKS)
    parser.add_argument(
        "--side", choices=("inside", "outside", "gray-inner-links"), default="inside"
    )
    args = parser.parse_args()
    execute(args.run.resolve(), args.network, args.side)
