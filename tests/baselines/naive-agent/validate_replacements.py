"""Independently replay the three replacement checks using the saved raw network observations."""

from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
from pathlib import Path

from architecture_cases import (
    FAMILIES,
    OBLIGATION,
    captured,
    complete_proof_input,
    proof_input,
)
from cohort import LIVE_RUN, NETWORKS, runtime_profile
from run_architecture_trial import (
    PROOF,
    proof,
    project_readings,
    validate_reading,
    verify_change,
    verify_restored,
    worker,
)
import secrets


def read(path):
    return json.loads(path.read_text())


def verify(folder, out, family, network, source, clean, final):
    p = runtime_profile(network)
    before, held, restored = [
        read(folder / name)
        for name in (
            "before.json",
            "independent-evidence.json",
            "restored-observations.json",
        )
    ]
    for reading in (before, held, restored):
        validate_reading(p, reading)
    device, description = verify_change(family, before, held)
    verify_restored(family, before, restored)
    if (
        not read(folder / "raw/capture.json")["converged"]
        or not read(folder / "restoration.json")["restored"]
    ):
        raise ValueError("Missing convergence or restoration")
    imported, witness = captured(folder / "raw/snapshot/native")
    if [held["evidence"], held["witness"]] != json.loads(
        json.dumps([imported, witness])
    ):
        raise ValueError(
            "The native snapshot differs from the independent live observations"
        )
    faulty = complete_proof_input(folder / "raw/snapshot/native")
    for part in ("reds", "edges", "levels", "regions"):
        if (
            json.loads(json.dumps(clean[part])) != before["evidence"][part]
            or json.loads(json.dumps(final[part])) != restored["evidence"][part]
        ):
            raise ValueError(
                f"The complete reference differs from the case's {part} observations"
            )
    statuses = []
    for phase, data, expected in (
        ("clean", clean, "pass"),
        ("fault", faulty, "rejected"),
        ("restored", final, "pass"),
    ):
        result = proof(data, out / phase, source)
        if result["status"] != expected:
            raise ValueError(f"{network}/{family}/{phase}: {result['status']}")
        failed = [line.split()[1] for line in result["failed_obligations"]]
        if failed != ([OBLIGATION[family]] if phase == "fault" else []):
            raise ValueError(f"Unexpected failed Lean obligation: {failed}")
        statuses.append(result["status"])
    if family == "shared-inner-gateway":
        measurement = [
            {
                "source": s["source"],
                "gateway": s["gateway"],
                "association": s["child"],
                "before": s["before"][s["child"]]["packets"],
                "after": s["after"][s["child"]]["packets"],
            }
            for s in held["shared_traffic"]
        ]
    elif family == "gray-cross-level-path":
        measurement = {
            "path": held["witness"]["gray_path"],
            "firewall_free_after_restore": restored["witness"]["gray_path"],
        }
    else:
        measurement = held["packet_observations"]
    return {
        "network": network,
        "measurement": measurement,
        "family": family,
        "device": device,
        "finding": description,
        "lean": statuses,
        "failed_obligation": OBLIGATION[family],
        "trial": str(folder.resolve()),
        "native_sha256": hashlib.sha256(
            (folder / "raw/snapshot/native/snapshot.json").read_bytes()
        ).hexdigest(),
    }


def verify_all(roots, dest, controls, restored_from=None):
    dest.mkdir(exist_ok=False, parents=True)
    fixed = dest / PROOF.name
    fixed.write_bytes(PROOF.read_bytes())
    clean, final = {}, {}
    for name in NETWORKS:
        captured_control = controls / "raw/controls" / name / "snapshot/native"
        clean[name] = complete_proof_input(captured_control)
        p = runtime_profile(name)
        rows = (
            read(restored_from / (name + ".json"))
            if restored_from
            else worker(p, FAMILIES[1], secrets.token_hex(8), "read")
        )
        directory = dest / "restored"
        directory.mkdir(exist_ok=True)
        (directory / (name + ".json")).write_text(json.dumps(rows) + "\n")
        final[name] = project_readings(p, rows, proof_input)
        if final[name] != clean[name]:
            raise ValueError(
                f"Post-experiment architecture or firewall policies differ from the clean control for {name}"
            )

    def replay(pair):
        family, name = pair
        folder = next(
            (
                root / family / name
                for root in roots
                if (root / family / name / "qualification.json").is_file()
            ),
            None,
        )
        if folder is None:
            raise ValueError(f"Missing qualification for {name}/{family}")
        return verify(
            folder, dest / family / name, family, name, fixed, clean[name], final[name]
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(replay, [(f, n) for f in FAMILIES for n in NETWORKS]))
    summary = {
        "scope": "live implementation qualifications",
        "networks": list(NETWORKS),
        "cases": result,
        "clean_controls": str(controls.resolve()),
        "restoration_readings": "restored/",
        "blind_detector_sessions": 0,
        "source_sha256": hashlib.sha256(fixed.read_bytes()).hexdigest(),
    }
    (dest / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("output", type=Path)
    cli.add_argument(
        "inputs", nargs="+", type=Path, help="Most recent qualification directory first"
    )
    cli.add_argument(
        "--controls",
        type=Path,
        default=LIVE_RUN,
        help="Frozen clean captures from the live run",
    )
    cli.add_argument(
        "--restored-from",
        type=Path,
        help="Replay already collected post-experiment readings offline",
    )
    args = cli.parse_args()
    print(
        len(
            verify_all(args.inputs, args.output, args.controls, args.restored_from)[
                "cases"
            ]
        ),
        "cases verified",
        flush=True,
    )
