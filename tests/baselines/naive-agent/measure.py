"""Read the interval inside Lean after imported evidence has been elaborated."""

import hashlib
import json
import os
import time
from pathlib import Path
import re
import shutil
import subprocess


def typecheck(source, directory, evidence, expected_lines):
    directory.mkdir(parents=True, exist_ok=False)
    target = directory / source.name
    shutil.copyfile(source, target)
    raw = (json.dumps(evidence, sort_keys=True) + "\n").encode()
    (directory / "evidence.json").write_bytes(raw)
    timeout = int(os.environ.get("TDN_BENCHMARK_LEAN_TIMEOUT", "300"))
    if not 1 <= timeout <= 3600:
        raise ValueError("Lean timeout must be between one second and one hour")
    started = time.monotonic()
    try:
        p = subprocess.run(
            [
                "lake",
                "env",
                "lean",
                "-j1",
                "-DmaxRecDepth=100000",
                "-DmaxHeartbeats=10000000",
                "--json",
                str(target.resolve()),
            ],
            cwd=Path(__file__).resolve().parents[3],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:

        def decoded(value):
            return (
                value.decode(errors="replace")
                if isinstance(value, bytes)
                else value or ""
            )

        (directory / "lean.jsonl").write_text(decoded(exc.stdout))
        (directory / "stderr.txt").write_text(decoded(exc.stderr))
        result = {
            "status": "timeout",
            "typecheck_ns": None,
            "wall_seconds": time.monotonic() - started,
            "limit_seconds": timeout,
            "source_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "failed_obligations": [],
            "returncode": 124,
            "errors": [],
        }
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    (directory / "lean.jsonl").write_text(p.stdout)
    (directory / "stderr.txt").write_text(p.stderr)
    messages = [json.loads(l) for l in p.stdout.splitlines() if l.startswith("{")]
    errors = [m for m in messages if m.get("severity") == "error"]

    def timestamp(name):
        found = [
            int(m["data"].strip().split()[-1])
            for m in messages
            if str(m.get("data", "")).startswith("TDN_" + name + " ")
        ]
        return found[0] if len(found) == 1 else None

    start, stop = timestamp("BEGIN"), timestamp("END")
    lines = target.read_text().splitlines()
    begin_line = next(i for i, l in enumerate(lines, 1) if 'm!"TDN_BEGIN ' in l)
    end_line = next(i for i, l in enumerate(lines, 1) if 'm!"TDN_END ' in l)
    known = {
        i
        for i, l in enumerate(lines, 1)
        if begin_line < i < end_line and l in expected_lines
    }
    failed = [
        e
        for e in errors
        if e.get("pos", {}).get("line") in known
        and "evaluated that the proposition" in str(e.get("data", ""))
        and "is false" in str(e.get("data", ""))
    ]
    status = "checker_error"
    if start is not None and stop is not None and stop >= start:
        if p.returncode == 0 and not errors:
            status = "pass"
        elif p.returncode and failed and len(failed) == len(errors):
            status = "rejected"
    result = {
        "status": status,
        "wall_seconds": time.monotonic() - started,
        "limit_seconds": timeout,
        "typecheck_ns": stop - start
        if start is not None and stop is not None and stop >= start
        else None,
        "source_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "failed_obligations": [
            next(
                (
                    l
                    for l in reversed(lines[: e["pos"]["line"]])
                    if re.match(r"^(?:lemma|theorem|example)\b", l)
                ),
                lines[e["pos"]["line"] - 1],
            )
            for e in failed
        ],
        "returncode": p.returncode,
        "errors": errors,
    }
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
