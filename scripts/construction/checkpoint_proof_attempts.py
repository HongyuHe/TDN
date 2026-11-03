"""Archive completed proof attempts and their exact, hash-checked inputs."""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tarfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--attempt-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    attempts = args.attempt_directory
    if not attempts.is_absolute():
        attempts = workspace / attempts
    attempts = attempts.resolve()
    if not (attempts / "experiments").is_dir():
        parser.error("Attempt directory must contain an experiments directory: " + str(attempts))
    files = {}
    selected = []

    def include(path, expected=None):
        path = path.resolve()
        relative = str(path.relative_to(workspace))
        if relative in files:
            if expected is not None:
                assert files[relative]["sha256"] == expected
            return
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if expected is not None:
            assert digest == expected, "Recorded source or log changed: " + relative
        files[relative] = {"path": path, "sha256": digest, "bytes": len(data)}

    for receipt in sorted((attempts / "experiments").glob("*.attempt.json")):
        record = json.loads(receipt.read_text())
        if record.get("finished_at") is None:
            continue
        include(receipt)
        include(workspace / record["log"], record["log_sha256"])
        source_receipt = workspace / record["source_checkpoint"]
        include(source_receipt)
        checkpoint = json.loads(source_receipt.read_text())
        for entry in checkpoint["files"]:
            include(workspace / checkpoint["checkpoint"] / entry["path"], entry["sha256"])
        selected.append({"receipt": str(receipt.relative_to(workspace)), "label": record["label"],
                         "exit_code": record["exit_code"], "finished_at": record["finished_at"]})
    for path in sorted((attempts / "proof-map-versions").glob("*.json")):
        include(path)
    if not selected:
        parser.error("No completed proof attempts were found in " + str(attempts))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"at": datetime.now(timezone.utc).isoformat(), "kind": "completed proof attempts; not a review verdict",
                "attempts": selected, "files": [{"path": name, "sha256": row["sha256"], "bytes": row["bytes"]}
                                                for name, row in sorted(files.items())]}
    with tarfile.open(args.output, "x:gz") as archive:
        for relative, entry in sorted(files.items()):
            data = entry["path"].read_bytes()
            assert hashlib.sha256(data).hexdigest() == entry["sha256"], "Input changed during archival"
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        data = (json.dumps(manifest, indent=2) + "\n").encode()
        info = tarfile.TarInfo("checkpoint-manifest.json")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    print(json.dumps({"attempts": len(selected), "files": len(files), "output": str(args.output),
                      "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
