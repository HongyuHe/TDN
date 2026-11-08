"""Run one bounded Lean process per source and retain its command and result."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=180)
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--olean", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()
    root = Path.cwd().resolve()
    source.relative_to(root)
    key = hashlib.sha256(str(source).encode()).hexdigest()[:16]
    state_dir = root / "outputs" / "processes"
    state_dir.mkdir(parents=True, exist_ok=True)
    lock = state_dir / (key + ".json")
    if args.stop:
        state = json.loads(lock.read_text())
        pid = state["pid"]
        if os.getpgid(pid) != pid:
            raise ValueError("recorded child no longer owns its process group")
        os.killpg(pid, signal.SIGTERM)
        print(json.dumps({"stopped": pid, "source": str(source)}))
        return
    args.log.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    started = datetime.now(timezone.utc).isoformat()
    command = ["lake", "env", "lean", str(source.relative_to(root))]
    if args.olean:
        output_module = root / ".lake/build/lib/lean" / source.relative_to(root).with_suffix(".olean")
        output_module.parent.mkdir(parents=True, exist_ok=True)
        command.extend(["-o", str(output_module)])
    status = {"source": str(source), "command": command, "started": started,
              "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "log": str(args.log)}
    process = None
    try:
        with args.log.open("x") as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            status["pid"] = process.pid
            os.write(fd, json.dumps(status).encode())
            os.close(fd)
            began = time.monotonic()
            try:
                code = process.wait(timeout=args.seconds)
                status["outcome"] = "completed"
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    code = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    code = process.wait()
                status["outcome"] = "time_limit"
            status["exit_code"] = code
            status["elapsed_seconds"] = time.monotonic() - began
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait()
        lock.unlink(missing_ok=True)
        status["finished"] = datetime.now(timezone.utc).isoformat()
        status["finished_source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        status["source_unchanged"] = status["finished_source_sha256"] == status["source_sha256"]
        if not status["source_unchanged"] and status.get("exit_code") == 0:
            status["outcome"] = "source_changed_during_run"
            status["exit_code"] = 1
        args.log.with_suffix(args.log.suffix + ".json").write_text(json.dumps(status, indent=2) + "\n")
    print(json.dumps(status))
    raise SystemExit(0 if status.get("exit_code") == 0 else 1)


if __name__ == "__main__":
    main()
