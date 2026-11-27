"""Keep the scored snapshot separate from the supervisor's case-specific confirmation."""

import hashlib
import json
from pathlib import Path
from time import monotonic_ns


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def capture_metadata(capture_dir):
    root = capture_dir/"snapshot"
    return {name:fingerprint(root/name) for name in ("spec.json","native/spec.json","enclave-policy.json","processing/manifest.json")
            if (root/name).is_file()}


def freeze_then_confirm(capture_dir, background_plan, collect, confirm):
    """Collect a fresh snapshot under a specified traffic plan, then obtain a separate observation."""
    if capture_dir.exists():
        raise ValueError("The capture needs a fresh directory")
    started = monotonic_ns()
    plan_hash = fingerprint(background_plan)
    collect()
    frozen = {
        "started_ns": started,
        "background_plan_sha256": plan_hash,
        "metadata_sha256": capture_metadata(capture_dir),
        "native_manifest_sha256": fingerprint(
            capture_dir / "snapshot/native/manifest.json"
        ),
        "processing_sha256": fingerprint(
            capture_dir / "snapshot/processing/observations.json"
        ),
    }
    receipt = capture_dir / "capture.json"
    if receipt.exists() and "control_variant" in json.loads(receipt.read_bytes()):
        frozen["capture_receipt_sha256"] = fingerprint(receipt)
    frozen["sealed_ns"] = monotonic_ns()
    write_new(capture_dir / "observation-seal.json", frozen)
    began = monotonic_ns()
    observation = Path(confirm())
    write_new(
        capture_dir / "confirmation.json",
        {
            "began_ns": began,
            "completed_ns": monotonic_ns(),
            "observation_sha256": fingerprint(observation),
            "seal_sha256": fingerprint(capture_dir / "observation-seal.json"),
        },
    )


def validate_window(capture_dir, plan_hash, observation_hash=None, *, require_metadata=False,
                    require_variant=False):
    seal = capture_dir / "observation-seal.json"
    receipt = capture_dir / "confirmation.json"
    if not seal.is_file() or not receipt.is_file():
        raise ValueError("Missing record of capture before independent confirmation")
    frozen = json.loads(seal.read_bytes())
    check = json.loads(receipt.read_bytes())
    if require_variant or "capture_receipt_sha256" in frozen:
        if frozen.get("capture_receipt_sha256") != fingerprint(capture_dir / "capture.json"):
            raise ValueError("The frozen capture receipt and control variant differ")
    metadata = frozen.get("metadata_sha256")
    if (metadata is not None and metadata != capture_metadata(capture_dir)) or (require_metadata and
            (metadata is None or set(metadata) != {"spec.json","native/spec.json","enclave-policy.json","processing/manifest.json"})):
        raise ValueError("The capture lacks the frozen design, security designations or processing manifest")
    if not (
        frozen["started_ns"]
        < frozen["sealed_ns"]
        <= check["began_ns"]
        <= check["completed_ns"]
    ):
        raise ValueError("Independent confirmation overlapped the scored capture")
    if (
        check["seal_sha256"] != fingerprint(seal)
        or frozen["native_manifest_sha256"]
        != fingerprint(capture_dir / "snapshot/native/manifest.json")
        or frozen["processing_sha256"]
        != fingerprint(capture_dir / "snapshot/processing/observations.json")
        or frozen["background_plan_sha256"] != plan_hash
    ):
        raise ValueError(
            "The scored capture or the registered background schedule differs"
        )
    if observation_hash is not None and check["observation_sha256"] != observation_hash:
        raise ValueError("The independent confirmation is from a different observation")
