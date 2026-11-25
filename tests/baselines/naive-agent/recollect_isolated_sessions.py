"""Archive unsettled captures after a network finishes, then repeat those cases."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from common import BASE, ROOT, now, run_remote
from run_isolated_theory import RUN_ID, REMOTE


def unsettled(folder):
    snapshot = json.loads((folder / "snapshot/native/snapshot.json").read_text())
    return any(any(word in t["observed_state"] for word in ["DELETING", "CONNECTING", "REKEYING"])
               for t in snapshot["tunnels"])


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("network")
    a = p.parse_args()
    root = BASE / "runs" / RUN_ID
    profile = json.loads((root / "profiles" / (a.network + ".json")).read_text())
    cases = [root / "cases" / c["case_id"] for c in profile["mutations"]]
    assert all((c / "completed.json").exists() for c in cases), "Finish the network before recollecting"
    selected = [c for c in cases if unsettled(c)]
    control = root / "controls" / a.network
    if unsettled(control):
        selected.append(control)
    for folder in selected:
        suffix = "-unsettled-snapshot" if folder.parent.name == "cases" else "-control-unsettled-snapshot"
        destination = root / "attempts" / (folder.name + suffix)
        assert not destination.exists()
        result = run_remote(["sudo", "-n", "mkdir", "-p", REMOTE + "/attempts"])
        assert result["returncode"] == 0
        relative = str(folder.relative_to(root))
        result = run_remote(["sudo", "-n", "mv", REMOTE + "/" + relative, REMOTE + "/attempts/" + destination.name])
        assert result["returncode"] == 0, result
        shutil.move(folder, destination)
        if folder.parent.name == "controls":
            shutil.move(root / "commands" / (a.network + "-baseline.json"), destination / "baseline-command.json")
        with (root / "events.jsonl").open("a") as stream:
            stream.write(json.dumps({"at": now(), "event": "recollection_requested", "network": a.network,
                "previous_capture": relative, "retained_at": str(destination.relative_to(root)),
                "reason": "Captured an IKE session still closing or connecting; repeat with settled sessions."}) + "\n")
    print(json.dumps({"network": a.network, "captures_to_repeat": len(selected)}), flush=True)
    if selected:
        raise SystemExit(subprocess.run([sys.executable, str(BASE / "run_isolated_theory.py"),
            "--resume", "--network", a.network], cwd=ROOT).returncode)
