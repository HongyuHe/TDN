#!/usr/bin/env python3
"""Preserve exact source before a command, then bind its durable output and status."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import signal
import time
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
            for match in re.finditer(r'\bload_network_records\b[^;]*?\bfrom\s+"([^"\n]+)"', path.read_text()):
                referenced = (path.parent / match.group(1)).resolve()
                candidates.append(str(referenced.relative_to(root)))
    return sorted(selected), sorted(missing)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--run-dir", default=os.environ.get("TDN_OUTPUT_DIR"))
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--input", action="append", default=[])
    parser.add_argument("--cancel-file")
    parser.add_argument("--term-grace", type=float, default=3.0)
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
    active_path = log.with_suffix(".active.json")
    cancel_path = Path(args.cancel_file) if args.cancel_file else log.with_suffix(".cancel")
    cancel_path = cancel_path.resolve()
    cancel_path.relative_to(root)
    process = None
    process_group = None
    termination_reason = None
    termination_signals = []
    cleanup_probe_errors = []
    exit_code = 127
    received_signal = {"number": None}
    old_handlers = {}
    for number in [signal.SIGINT, signal.SIGTERM]:
        old_handlers[number] = signal.signal(number, lambda value, frame: received_signal.update(number=value))
    active = {"status": "starting", "active": False, "label": args.label,
              "started_at": start.isoformat(), "command": command,
              "source_checkpoint": output, "log": str(log),
              "cancel_file": str(cancel_path.relative_to(root)), "pid": None, "process_group": None}
    def save_active():
        temporary = active_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(active, indent=2) + "\n")
        temporary.replace(active_path)
    def group_exists():
        if process_group is None:
            return False
        try:
            os.killpg(process_group, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError as error:
            cleanup_probe_errors.append({"at": datetime.now(timezone.utc).isoformat(), "error": str(error)})
            return None
    def send_group(number, name):
        try:
            os.killpg(process_group, number)
            termination_signals.append(name)
        except ProcessLookupError:
            pass
        except PermissionError as error:
            cleanup_probe_errors.append({"at": datetime.now(timezone.utc).isoformat(),
                                         "operation": name, "error": str(error)})

    def stop_group():
        observed = group_exists()
        if observed is False:
            return
        if observed is True or (process is not None and process.poll() is None):
            send_group(signal.SIGTERM, "TERM")
            deadline = time.monotonic() + args.term_grace
            while group_exists() is True and time.monotonic() < deadline:
                if process is not None:
                    process.poll()
                time.sleep(0.05)
            if group_exists() is True:
                send_group(signal.SIGKILL, "KILL")
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=args.term_grace)
            except subprocess.TimeoutExpired:
                cleanup_probe_errors.append({"at": datetime.now(timezone.utc).isoformat(),
                                             "operation": "wait", "error": "Child termination unconfirmed"})

    try:
        save_active()
        with log.open("w") as stream:
            try:
                if cancel_path.exists():
                    raise ValueError("Cancellation request exists before command launch")
                process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                process_group = process.pid
                active.update(status="running", active=True, pid=process.pid, process_group=process_group)
                save_active()
                deadline = time.monotonic() + args.timeout if args.timeout is not None else None
                while process.poll() is None:
                    if cancel_path.exists():
                        termination_reason = "cancellation-request"
                    elif received_signal["number"] is not None:
                        termination_reason = "recorder-signal-" + str(received_signal["number"])
                    elif deadline is not None and time.monotonic() >= deadline:
                        termination_reason = "timeout"
                    if termination_reason is not None:
                        active.update(status="stopping", termination_reason=termination_reason)
                        save_active()
                        stop_group()
                        break
                    try:
                        process.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        pass
                exit_code = process.poll()
                if exit_code is None:
                    exit_code = 127
                if termination_reason == "timeout":
                    exit_code = 124
                elif termination_reason is not None:
                    exit_code = 130
                if group_exists() is True:
                    stop_group()
            except Exception as error:
                launch_error = type(error).__name__ + ": " + str(error)
                traceback.print_exc(file=stream)
                if process is not None:
                    stop_group()
                exit_code = 127
    finally:
        for number, previous in old_handlers.items():
            signal.signal(number, previous)
        finished = datetime.now(timezone.utc).isoformat()
        observed_group = group_exists()
        observed_child = process is not None and process.poll() is None
        active.update(status="finished" if not observed_child else "cleanup-unconfirmed", active=observed_child,
                      finished_at=finished, termination_reason=termination_reason,
                      termination_signals=termination_signals,
                      process_group_exists_after_cleanup=observed_group, exit_code=exit_code,
                      cleanup_probe_errors=cleanup_probe_errors)
        record = {
            "label": args.label, "started_at": start.isoformat(), "finished_at": finished,
            "command": command, "source_checkpoint": output,
            "additional_inputs": inputs, "missing_inputs": missing_inputs,
            "log": str(log), "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest() if log.exists() else None,
            "exit_code": exit_code, "launch_error": launch_error,
            "active_record": str(active_path), "pid": process.pid if process is not None else None,
            "process_group": process_group, "termination_reason": termination_reason,
            "termination_signals": termination_signals, "cleanup_probe_errors": cleanup_probe_errors,
            "process_group_exists_after_cleanup": observed_group,
            "child_running_after_cleanup": observed_child,
            "cwd": str(root), "timeout_seconds": args.timeout,
            "lean_toolchain": Path("lean-toolchain").read_text().strip(),
            "lake_manifest_sha256": hashlib.sha256(Path("lake-manifest.json").read_bytes()).hexdigest()
        }
        destination = log.with_suffix(".attempt.json")
        try:
            save_active()
        finally:
            destination.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    print("\n".join(log.read_text(errors="replace").splitlines()[-60:]))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
