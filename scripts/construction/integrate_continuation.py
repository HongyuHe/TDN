"""Plan or apply reviewed continuation checkpoints while preserving local edits."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil


COORDINATOR_FILES = {
    "start_continuation.py", "collect_continuation.py", "audit_continuation.py",
    "handoff_continuation.py",
    "integrate_continuation.py",
    "audit_snapshot_integrity.py", "audit_recorded_controls.py",
    "promote_validated_checkpoint.py",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def owned(actor, name):
    path = Path(name)
    if "__pycache__" in path.parts or path.suffix == ".pyc":
        return False
    if actor == "evidence":
        return name.startswith("scripts/construction/evidence/")
    if name.startswith(("TDN/", "tests/")):
        return True
    if name in {"TDN.lean", "lakefile.toml", "lake-manifest.json", "lean-toolchain"}:
        return True
    return (path.parent == Path("scripts/construction")
            and path.name not in COORDINATOR_FILES)


def applied_baseline(run, initial):
    """Use the last applied bytes as the base for each subsequent merge."""
    before = dict(initial)
    records = []
    for path in sorted((run / "integration").glob("*/result.json")):
        result = json.loads(path.read_text())
        if result.get("applied") is not True:
            continue
        if result.get("conflicts"):
            raise ValueError("An applied integration records unresolved conflicts")
        for entry in result["changes"]:
            name = entry["path"]
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("Previous integration path escapes project")
            before[name] = entry["proposed_sha256"]
        records.append({"path": str(path.relative_to(run)), "sha256": digest(path)})
    return before, records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--construction-checkpoint", required=True)
    parser.add_argument("--evidence-checkpoint", required=True)
    parser.add_argument("--actors", nargs="+", choices=["construction", "evidence"],
                        default=["construction", "evidence"])
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    run = root / "artifacts/construction" / args.run
    baseline_manifests = sorted((run / "history").glob("*-coordinator/manifest.json"))
    if len(baseline_manifests) != 1:
        raise ValueError("Expected exactly one initial coordinator checkpoint")
    baseline = json.loads(baseline_manifests[0].read_text())
    initial = {item["path"]: item["sha256"] for item in baseline["files"]}
    before, integration_bases = applied_baseline(run, initial)
    changes = []
    conflicts = []
    for actor in dict.fromkeys(args.actors):
        identity = getattr(args, actor + "_checkpoint")
        if len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
            raise ValueError("Checkpoint must be its content-hash directory name")
        checkpoint = run / "checkpoints" / actor / identity
        manifest = json.loads((checkpoint / "manifest.json").read_text())
        after = {item["path"]: item["sha256"] for item in manifest["files"]}
        for name in sorted(set(before) | set(after)):
            if not owned(actor, name):
                continue
            path = Path(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Checkpoint path escapes project")
            original, proposed = before.get(name), after.get(name)
            if original == proposed:
                continue
            source = checkpoint / path
            target = root / path
            if target.is_symlink() or source.is_symlink():
                raise ValueError("Source integration does not follow symlinks")
            if digest(source) != proposed:
                raise ValueError("Checkpoint content changed: " + name)
            current = digest(target)
            if current == proposed:
                continue
            entry = {"actor": actor, "path": name, "baseline_sha256": original,
                     "current_sha256": current, "proposed_sha256": proposed,
                     "checkpoint": str(checkpoint.relative_to(root)),
                     "action": "remove" if proposed is None else "write"}
            if current != original:
                conflicts.append(entry)
            else:
                changes.append(entry)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    record = {"at": stamp, "applied": False, "changes": changes, "conflicts": conflicts,
              "previous_applied_integrations": integration_bases, "actors": args.actors}
    destination = run / "integration" / stamp
    destination.mkdir(parents=True)
    (destination / "plan.json").write_text(json.dumps(record, indent=2) + "\n")
    if args.apply:
        if conflicts:
            raise ValueError("Local edits conflict; inspect the saved integration plan")
        #* Check the complete plan before modifying any working file.
        for entry in changes:
            if digest(root / entry["path"]) != entry["current_sha256"]:
                raise ValueError("Working file changed during planning")
        for entry in changes:
            target = root / entry["path"]
            if target.exists():
                backup = destination / "before" / entry["path"]
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, backup)
            if entry["action"] == "remove":
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(root / entry["checkpoint"] / entry["path"], target)
        record["applied"] = True
        (destination / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"plan": str((destination / "plan.json").relative_to(root)),
                      "changes": len(changes), "conflicts": len(conflicts),
                      "applied": record["applied"]}))


if __name__ == "__main__":
    main()
