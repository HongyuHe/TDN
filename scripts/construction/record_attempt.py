#!/usr/bin/env python3
"""Preserve exact source before a command, then bind its durable output and status."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import traceback
from pathlib import Path
import subprocess
import sys
import uuid


def referenced_inputs(root, command, explicit):
    root = root.resolve()
    candidates = list(explicit)
    candidates.extend(word for word in command if Path(word).suffix in {".lean", ".py", ".json"})
    selected, missing, visited = [], [], set()
    while candidates:
        name = candidates.pop(0)
        path = (root / name).resolve()
        relative = str(path.relative_to(root))
        if relative in visited:
            continue
        visited.add(relative)
        if any(part in {"private", "secrets", "pki", ".git", ".lake"} for part in Path(relative).parts):
            raise ValueError("Private or generated inputs cannot be captured: " + relative)
        if not path.exists():
            missing.append(relative)
            continue
        if not path.is_file():
            raise ValueError("An explicit attempt input must be a file: " + relative)
        selected.append(relative)
        if path.suffix == ".lean":
            for match in re.finditer(r'\btdn_data\b[^;]*?\bfrom\s+"([^"\n]+)"', path.read_text()):
                referenced = (path.parent / match.group(1)).resolve()
                candidates.append(str(referenced.relative_to(root)))
    return sorted(selected), sorted(missing)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--run-dir", default=os.environ.get("TDN_OUTPUT_DIR"))
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--input", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    if not args.run_dir:
        parser.error("--run-dir or TDN_OUTPUT_DIR is required")
    root = Path.cwd().resolve()
    run_dir = Path(args.run_dir).resolve()
    run_dir.relative_to(root)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "experiments").mkdir(exist_ok=True)
    run_dir = run_dir.relative_to(root)
    start = datetime.now(timezone.utc)
    stamp = start.strftime("%Y%m%dT%H%M%S.%fZ") + "-" + uuid.uuid4().hex
    inputs, missing_inputs = referenced_inputs(root, command, args.input)
    output = subprocess.check_output([
        sys.executable, "scripts/construction/record.py", "checkpoint",
        "--actor", "construction", "--label", args.label,
        "--reason", "Preserve exact sources before executing a validation or proof attempt",
        "--details", json.dumps({"command": command, "additional_inputs": inputs,
                                  "missing_inputs": missing_inputs}),
        "--history-dir", str(run_dir / "history"),
        "--paths", "TDN", "TDN.lean", "lakefile.lean", "lakefile.toml", "lake-manifest.json",
        "lean-toolchain", "scripts/construction", "tests", "data/evidence", *inputs
    ], text=True).strip()
    log = run_dir / "experiments" / (stamp + "-" + args.label + ".log")
    launch_error = None
    with log.open("w") as stream:
        try:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=args.timeout)
            exit_code = result.returncode
        except Exception as error:
            launch_error = type(error).__name__ + ": " + str(error)
            traceback.print_exc(file=stream)
            exit_code = 124 if isinstance(error, subprocess.TimeoutExpired) else 127
    record = {
        "label": args.label, "started_at": start.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "command": command, "source_checkpoint": output,
        "additional_inputs": inputs, "missing_inputs": missing_inputs,
        "log": str(log), "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        "exit_code": exit_code, "launch_error": launch_error,
        "cwd": str(root), "timeout_seconds": args.timeout,
        "lean_toolchain": Path("lean-toolchain").read_text().strip(),
        "lake_manifest_sha256": hashlib.sha256(Path("lake-manifest.json").read_bytes()).hexdigest()
    }
    destination = log.with_suffix(".attempt.json")
    destination.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    print("\n".join(log.read_text(errors="replace").splitlines()[-60:]))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
