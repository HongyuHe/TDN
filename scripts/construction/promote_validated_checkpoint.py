"""Preserve the exact source checkpoint used by a successful recorded Lean build."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative_path(value):
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Expected a path relative to the actor workspace")
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--attempt", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    run_relative = Path("artifacts/construction") / relative_path(args.run)
    run = root / run_relative
    session = json.loads((run / "session.json").read_text())
    actor = Path(session["workspaces"]["construction"]["path"])
    attempt_relative = relative_path(args.attempt)
    if not attempt_relative.is_relative_to(run_relative / "experiments"):
        raise ValueError("Attempt must belong to the selected run")
    attempt_path = actor / attempt_relative
    attempt = json.loads(attempt_path.read_text())
    if attempt["exit_code"] != 0 or attempt["command"] != ["lake", "build"]:
        raise ValueError("A successful complete Lean build is required")
    log_relative = relative_path(attempt["log"])
    if digest(actor / log_relative) != attempt["log_sha256"]:
        raise ValueError("Build log changed")
    record_relative = relative_path(attempt["source_checkpoint"])
    record = json.loads((actor / record_relative).read_text())
    source = actor / relative_path(record["checkpoint"])
    files = []
    for item in record["files"]:
        path = relative_path(item["path"])
        allowed = path.parts[0] in {"TDN", "tests"} or path.is_relative_to("scripts/construction")
        allowed = allowed or str(path) in {"TDN.lean", "lakefile.toml", "lake-manifest.json", "lean-toolchain"}
        if not allowed or (source / path).is_symlink() or digest(source / path) != item["sha256"]:
            raise ValueError("Invalid or changed source file: " + str(path))
        files.append({"path": str(path), "sha256": item["sha256"]})
    files.sort(key=lambda item: item["path"])
    signature = hashlib.sha256(json.dumps(files).encode()).hexdigest()
    destination = run / "checkpoints/construction" / signature
    if not destination.exists():
        destination.mkdir(parents=True)
        for item in files:
            target = destination / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / item["path"], target)
        manifest = {"at": datetime.now(timezone.utc).isoformat(), "files": files,
                    "source_record": str(record_relative), "build_attempt": str(attempt_relative),
                    "build_attempt_sha256": digest(attempt_path)}
        (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    #* Keep the successful command record and its log beside the collected actor records.
    for relative in [attempt_relative, log_relative, record_relative]:
        target = run / "agents/construction" / relative.relative_to(run_relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and digest(target) != digest(actor / relative):
            raise ValueError("Previously collected validation record changed")
        shutil.copy2(actor / relative, target)
    print(json.dumps({"checkpoint": signature, "files": len(files), "build_attempt": str(attempt_relative)}))


if __name__ == "__main__":
    main()
