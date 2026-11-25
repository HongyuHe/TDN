"""Retain unsettled collections and retry while the same isolated fault is present."""

from datetime import datetime, timezone
import json

from capture_live import capture


def capture_stable(profile, destination, attempts=4):
    for index in range(1, attempts + 1):
        result = capture(profile, destination)
        if result["converged"]:
            return result
        manifest = destination / "snapshot/native/manifest.json"
        changed = (
            json.loads(manifest.read_text())["convergence"]["changed"]
            if manifest.exists()
            else []
        )
        record = {
            "at": datetime.now(timezone.utc).isoformat(),
            "attempt": index,
            "changed": changed,
        }
        (destination / "unsettled.json").write_text(json.dumps(record, indent=2) + "\n")
        if index < attempts:
            prior = (
                destination.parent
                / "capture-attempts"
                / destination.name
                / f"{index:02d}"
            )
            prior.parent.mkdir(parents=True, exist_ok=True)
            if prior.exists():
                raise FileExistsError(prior)
            destination.rename(prior)
    return result
