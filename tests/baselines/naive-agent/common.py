"""Shared experiment paths, records, and SSH execution."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import time


ROOT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parent
WORKER = "hy@clnode176.clemson.cloudlab.us"
PROFILE_NAMES = [
    "ipsec-baseline",
    "shared-same-level",
    "shared-four-levels",
    "redundant-four-levels",
    "management-independent",
]


def now():
    return datetime.now(timezone.utc).isoformat()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def run_remote(argv, worker=WORKER, input_bytes=None, timeout=120):
    started = time.monotonic()
    process = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
         "-o", "ControlMaster=auto", "-o", "ControlPersist=120",
         "-o", "ControlPath=/tmp/tdn-baseline-%C", worker, shlex.join(argv)],
        input=input_bytes, capture_output=True, timeout=timeout,
    )
    return {
        "worker": worker, "argv": argv, "returncode": process.returncode,
        "stdout": process.stdout.decode(errors="replace"),
        "stderr": process.stderr.decode(errors="replace"),
        "elapsed_seconds": time.monotonic() - started, "ended_at": now(),
    }


def remote_python(program, arguments=(), timeout=120):
    return run_remote(["sudo", "-n", "python3", "-", *arguments],
                      input_bytes=program.encode(), timeout=timeout)
