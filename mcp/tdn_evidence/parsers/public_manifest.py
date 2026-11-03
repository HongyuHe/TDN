"""Validate complete public experiment manifests before reading observations."""
import hashlib
import json
from .snapshot import require


def validate_files(path):
    manifest = json.loads((path / "manifest.json").read_text())
    names = [row["path"] for row in manifest["files"]]
    require(len(names) == len(set(names)), "Duplicate manifest path")
    actual = {str(p.relative_to(path)) for p in path.rglob("*") if p.is_file() and p != path / "manifest.json"}
    require(set(names) == actual, "Manifest does not cover every public input")
    for row in manifest["files"]:
        target = (path / row["path"]).resolve()
        target.relative_to(path.resolve())
        require(hashlib.sha256(target.read_bytes()).hexdigest() == row["sha256"], "Public file hash mismatch")
    return hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest()


