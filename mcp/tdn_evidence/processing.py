"""Expose hash-validated supplemental processing observations without interpreting them."""

import hashlib
import json
from pathlib import Path

from .parsers.public_manifest import validate_files
from .parsers.snapshot import require
from .saved import validated_snapshot


def validated_processing(snapshot_directory, supplement_directory):
    _, snapshot, _ = validated_snapshot(Path(snapshot_directory))
    root = Path(supplement_directory)
    manifest_hash = validate_files(root)
    document = json.loads((root / "observations.json").read_text())
    require(document.get("schema_version") in {"processing-evidence/v1", "csfc-processing-supplement/v1"},
            "Unknown processing observation schema")
    expected = document["expected_device_ids"]
    devices = {row["id"] for row in snapshot["devices"]}
    require(len(expected) == len(set(expected)) and set(expected) == devices, "Supplement device coverage mismatch")
    records = document["records"]
    require(len({row["id"] for row in records}) == len(records), "Duplicate processing observation")
    for row in records:
        require(row["device_id"] in devices, "Processing observation has an unknown device")
        require(row["phase"] in {"before", "after"}, "Unknown processing observation phase")
        require(type(row["returncode"]) is int and isinstance(row["stdout"], str) and isinstance(row["stderr"], str),
                "Malformed processing command result")
        require(isinstance(row["command"], list) and all(isinstance(word, str) for word in row["command"]),
                "Malformed processing command")
        require(isinstance(row["kind"], str) and row["kind"], "Missing processing observation kind")
    return document, manifest_hash


def query_processing(snapshot_directory, supplement_directory, collection, category, device, offset, limit):
    document, manifest_hash = validated_processing(snapshot_directory, supplement_directory)
    devices = set(document["expected_device_ids"])
    if device is not None and device not in devices:
        raise ValueError("Unknown device")
    kind = category.removeprefix("processing.") if category != "processing" else None
    if kind is not None and kind not in {row["kind"] for row in document["records"]}:
        raise ValueError("Unknown processing observation kind")
    selected = [row for row in document["records"]
                if (device is None or row["device_id"] == device) and (kind is None or row["kind"] == kind)]
    rows = [{"observation": row["id"], "device": row["device_id"], "category": "processing." + row["kind"],
             "source_uri": f"evidence://{collection}/raw/supplement:{row['id']}",
             "source_sha256": hashlib.sha256(row["stdout"].encode()).hexdigest(), "record": row}
            for row in selected]
    end = min(offset + limit, len(rows))
    return {"collection": collection, "source_kind": "saved_processing_supplement", "records": rows[offset:end],
            "total": len(rows), "next_offset": end if end < len(rows) else None,
            "manifest_sha256": manifest_hash, "started_at": document["started_at"], "ended_at": document["ended_at"],
            "requested_capability_collected": bool(selected),
            "coverage": [{"observation": row["id"], "device": row["device_id"], "phase": row["phase"],
                          "exit_code": row["returncode"], "status": "collected" if row["returncode"] == 0 else "failed",
                          "stderr_uri": f"evidence://{collection}/stderr/supplement:{row['id']}"} for row in selected],
            "devices_without_observation": sorted(({device} if device else devices) - {row["device_id"] for row in selected}),
            "limitations": document.get("limitations", []) + ["Raw command observations; no additional semantic interpretation."]}


def read_processing(snapshot_directory, supplement_directory, observation):
    document, _ = validated_processing(snapshot_directory, supplement_directory)
    selected = [row for row in document["records"] if row["id"] == observation]
    require(len(selected) == 1, "Unknown processing observation")
    return json.dumps(selected[0], indent=2) + "\n"
