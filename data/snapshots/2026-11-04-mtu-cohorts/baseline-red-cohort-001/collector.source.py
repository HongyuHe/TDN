#!/usr/bin/env python3
"""Surround native snapshot collection with public key-correlation observations."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def collect(args):
    args.output.mkdir(parents=True, exist_ok=False)
    tools = Path(__file__).resolve().parent
    stages = [
        ("keys-before", "native_ipsec_correlation.py", []),
        ("snapshot", "collect_native_v2.py", ["--configuration-id", args.configuration_id,
            "--run-id", args.run_id, "--platform-interface-names", args.platform_interface_names]),
        ("processing", "collect_processing.py", []),
        ("keys-after", "native_ipsec_correlation.py", []),
    ]
    records = []
    shutil.copy2(__file__, args.output / "collector.source.py")
    for stage, script, extra in stages:
        command = [sys.executable, str(tools / script), "--spec", str(args.spec.resolve()),
                   "--output", str((args.output / stage).resolve()), *extra]
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = subprocess.run(command, capture_output=True, text=True)
        records.append({"stage": stage, "command": command, "started_at": started,
            "ended_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "collector_sha256": hashlib.sha256((tools / script).read_bytes()).hexdigest()})
        (args.output / "sequence.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps({"stage": stage, "returncode": result.returncode}), flush=True)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--configuration-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--platform-interface-names", default="gre0,gretap0,erspan0")
    collect(parser.parse_args())
