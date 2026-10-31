"""Check preserved snapshot bytes without interpreting their network behavior."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def audit(root):
    records = []
    failures = []
    file_count = 0
    for manifest in sorted(root.rglob("manifest.json")):
        record = {"manifest": str(manifest.relative_to(root)), "files": 0}
        try:
            if manifest.is_symlink():
                raise ValueError("Manifest is a symlink")
            record["sha256"] = digest(manifest)
            data = json.loads(manifest.read_text())
            files = data.get("files", [])
            if not isinstance(files, list):
                raise ValueError("Manifest files must be a list")
            seen = set()
            for item in files:
                relative = Path(item["path"])
                if relative.is_absolute() or ".." in relative.parts or str(relative) in seen:
                    raise ValueError("Unsafe or duplicate file path: " + str(relative))
                seen.add(str(relative))
                path = manifest.parent
                for part in relative.parts:
                    path = path / part
                    if path.is_symlink():
                        raise ValueError("Symlink in file path: " + str(relative))
                if not path.resolve().is_relative_to(manifest.parent.resolve()):
                    raise ValueError("File leaves its bundle: " + str(relative))
                if not path.is_file():
                    raise ValueError("Missing file: " + str(relative))
                if "bytes" in item and path.stat().st_size != item["bytes"]:
                    raise ValueError("Size mismatch: " + str(relative))
                if digest(path) != item["sha256"]:
                    raise ValueError("Hash mismatch: " + str(relative))
                record["files"] += 1
                file_count += 1
        except (ValueError, KeyError, TypeError, OSError) as error:
            failures.append({"manifest": record["manifest"], "error": str(error)})
        records.append(record)
    return {"at": datetime.now(timezone.utc).isoformat(), "root": str(root),
            "scope": "Preserved file identity and path safety only; network claims require separate checks.",
            "manifests": len(records), "files": file_count,
            "failures": failures, "records": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if Path(args.run).name != args.run:
        parser.error("Run must be one directory name")
    root = Path(__file__).resolve().parents[2] / "data/snapshots" / args.run
    if not root.is_dir():
        parser.error("Snapshot run directory does not exist")
    result = audit(root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        parser.error("Refusing to overwrite a previous audit")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("at", "manifests", "files", "failures")}))
    raise SystemExit(bool(result["failures"]))


if __name__ == "__main__":
    main()
