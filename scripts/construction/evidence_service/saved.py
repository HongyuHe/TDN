"""Read the original v3 snapshots without weakening their existing validation."""
import hashlib
import json
from pathlib import Path


def validated_snapshot(directory):
    from .parsers.snapshot import validate_bundle
    validation = validate_bundle(directory)
    return json.loads((directory / "manifest.json").read_text()), json.loads((directory / "snapshot.json").read_text()), validation


def query_snapshot(directory, category, device, offset, limit):
    manifest, snapshot, validation = validated_snapshot(directory)
    if device is not None and device not in {d["id"] for d in snapshot["devices"]}:
        raise ValueError("Unknown device")
    categories = [category] if category is not None else ["devices", "interfaces", "links", "routes", "filters", "tunnels", "credentials", "probes"]
    if set(categories) - set(snapshot):
        raise ValueError("Unknown saved snapshot category")
    observations = {o["id"]: o for o in snapshot["observations"]}
    rows = []
    for key in categories:
        for record in snapshot[key]:
            if device is not None and record.get("device_id", record.get("id")) != device:
                continue
            rows.append({"category": key, "record": record, "sources": [observations[o] for o in record.get("observation_ids", [])]})
    end = min(offset + limit, len(rows))
    return {"collection": snapshot["snapshot_id"], "source_kind": "saved", "total": len(rows), "records": rows[offset:end],
            "next_offset": end if end < len(rows) else None, "inventory_complete": manifest["inventory_complete"],
            "convergence": manifest["convergence"], "validation": validation,
            "manifest_sha256": hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest()}
