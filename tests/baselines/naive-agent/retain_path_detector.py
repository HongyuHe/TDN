"""Retain a completed path-property trial and its observable execution record."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import shutil
import tarfile

from common import BASE, now, sha256, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("workspace", type=Path)
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    run = BASE / "runs" / args.run_id
    destination = run / "detector"
    if destination.exists():
        raise ValueError("Completed Detector records already exist")
    assert (args.workspace / "output/results.json").exists()
    records = [json.loads(line) for line in args.trace.read_text().splitlines()]
    events = [r for r in records if r["type"] == "event_msg"]
    started = next(r["timestamp"] for r in events if r["payload"].get("type") == "task_started")
    completed = [r["timestamp"] for r in events if r["payload"].get("type") == "task_complete"]
    if not completed:
        raise ValueError("Agent has not completed")
    ended = completed[-1]
    context = next(r["payload"] for r in records if r["type"] == "turn_context")
    calls = [{"timestamp": r["timestamp"], "name": r["payload"]["name"],
              "arguments": r["payload"].get("input", r["payload"].get("arguments"))}
             for r in records if r["type"] == "response_item"
             and r["payload"].get("type") in {"custom_tool_call", "function_call"}]
    token = json.loads((args.workspace / "access.json").read_text())["token"]
    assert token not in json.dumps(calls)
    shutil.copytree(args.workspace / "output", destination / "output")
    scratch = destination / "scratch"
    scratch.mkdir()
    for source in (args.workspace / "scratch").iterdir():
        if source.is_file() and source.suffix in {".py", ".log", ".jsonl"}:
            assert token not in source.read_text()
            shutil.copy2(source, scratch / source.name)
    with tarfile.open(run / "detector-derived-records.tar.gz", "w:gz") as archive:
        for source in sorted((args.workspace / "scratch").rglob("*")):
            if source.is_file() and "__pycache__" not in source.parts:
                if source.suffix != ".png":
                    assert token.encode() not in source.read_bytes()
                archive.add(source, arcname=str(source.relative_to(args.workspace)))
    write_json(run / "detector-tool-calls.json", calls)
    seconds = (datetime.fromisoformat(ended.replace("Z", "+00:00"))
               - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds()
    observations = [json.loads(p.read_text()) for p in (run / "detector-session/observations").glob("*.json")]
    requests = [json.loads(line) for line in (run / "detector-session/requests.jsonl").read_text().splitlines()]
    write_json(run / "detector-runtime.json", {
        "recorded_at": now(), "started_at": started, "ended_at": ended,
        "runtime_seconds": seconds, "model": context["model"], "reasoning_effort": context.get("effort"),
        "tool_invocations": len(calls), "gateway_requests": len(requests),
        "device_observations": len(observations),
        "failed_device_observations": sum(o["returncode"] != 0 for o in observations),
        "trace_sha256": sha256(args.trace.read_bytes()),
        "results_sha256": sha256((destination / "output/results.json").read_bytes()),
        "scope": "Elapsed agent time, including document reading, tool setup, live collection, analysis, and result writing. Supervisor setup and adjudication are outside the interval.",
    })
    print(json.dumps({"runtime_seconds": seconds, "model": context["model"],
                      "reasoning_effort": context.get("effort"), "tool_invocations": len(calls)}))


if __name__ == "__main__":
    main()
