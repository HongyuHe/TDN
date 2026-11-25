"""Run one applicable case on an original benchmark network and retain its baseline checks."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from attachment_view import live
from mode_lab import profile, remote
from observe_controls import HERE, NETWORKS
from restore_health import verify
from run_delivery_trial import execute as check_permission
from run_mode_trial import execute as check_connection
from run_unplug_trial import execute as check_attachment
from score_trials import KNOWN_TYPES


def control(network):
    declared = profile(network)
    before = live(declared)
    bad_links = [
        link for link in before["links"] if not (link["up"] and link["reciprocal"])
    ]
    if bad_links:
        return {"network": network, "ready": False, "unexpected_links": bad_links}
    health = verify(declared)
    return {
        "network": network,
        "ready": health["ready"],
        "healthy_links": len(before["links"]),
        **health,
    }


def execute(run, network, kind):
    run = run.resolve()
    scope = json.loads((HERE / "clause_scope.json").read_text())
    clauses = KNOWN_TYPES[kind]["clause_ids"]
    if all(scope[c]["scope"][network] == "inapplicable" for c in clauses):
        raise ValueError(f"The activation condition for {kind} is absent on {network}.")
    if (run / "trials" / kind / network).exists():
        raise FileExistsError(
            "A trial already exists for the selected type and network."
        )
    held = remote(
        "import json; from pathlib import Path; print(json.dumps(Path('/var/tmp/tdn-naive-rg-mode-lease').exists()))",
        {},
    )
    if held:
        raise RuntimeError(
            "A trial is still active. The next trial requires verified restoration."
        )
    start = datetime.now(timezone.utc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        checks = list(pool.map(control, NETWORKS))
    folder = run / "preflight" / kind / network
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / (start.strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    sources = (
        "run_case.py",
        "blind_audit.py",
        "reader.py",
        "capture_stable.py",
        "capture_live.py",
        "delivery_lab.py",
        "local_packet_probe.py",
        "peer_lab.py",
        "mode_lab.py",
        "unplug_lab.py",
        "link_parking_worker.py",
        "run_delivery_trial.py",
        "run_mode_trial.py",
        "run_unplug_trial.py",
        "gray_connectivity.py",
        "restore_health.py",
        "measure.py",
        "full_suite.py",
        "delivery_paths.py",
    )
    target.write_text(
        json.dumps(
            {
                "started_at": start.isoformat(),
                "networks": checks,
                "source_sha256": {
                    n: hashlib.sha256((HERE / n).read_bytes()).hexdigest()
                    for n in sources
                },
            },
            indent=2,
        )
        + "\n"
    )
    if not all(c["ready"] for c in checks):
        raise ValueError(
            "The clean peer, link or delivery controls need attention. See "
            + str(target)
        )
    if kind in ("inner-mode", "outer-mode", "inner-peer-loopback"):
        field = {
            "inner-mode": "inner",
            "outer-mode": "outer",
            "inner-peer-loopback": "inner-peer",
        }[kind]
        check_connection(run, network, field)
    elif kind == "gray-firewall-detached":
        check_attachment(run, network, "gray-inner-links")
    elif kind in ("firewall-inside-disconnected", "firewall-outside-disconnected"):
        check_attachment(run, network, kind.split("-")[1])
    else:
        check_permission(run, network, kind)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("network", choices=NETWORKS)
    parser.add_argument("case", choices=KNOWN_TYPES)
    args = parser.parse_args()
    execute(args.run, args.network, args.case)
