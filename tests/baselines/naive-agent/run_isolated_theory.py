"""Run clean -> one live mutation -> fresh snapshot -> Lean -> restore, per network."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import threading
import time

from common import BASE, ROOT, WORKER, now, run_remote, write_json

sys.path.insert(0, str(ROOT / "mcp"))
from tdn_evidence.parsers.execution import parse_execution

RUN_ID = "20261112-isolated-theory-01"
REMOTE = "/users/hy/tdn-isolated-theory-20261112"
ORIGINAL = "/users/hy/tdn-agent-baseline-20261112"
PREVIOUS = BASE / "runs/20261112-blind-theory-01"
LOCK = threading.Lock()
LEAN_JOBS = threading.Semaphore(3)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def event(root, kind, **fields):
    row = {"at": now(), "event": kind, **fields}
    with LOCK:
        with (root / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)


def remote(phase, profile, case=None):
    args = ["sudo", "-n", "python3", REMOTE + "/sources/isolated_worker.py", phase,
            "--root", REMOTE, "--baseline", ORIGINAL,
            "--profile", REMOTE + "/profiles/" + profile.name, "--sources", REMOTE + "/sources"]
    if case:
        args += ["--case", case]
    return run_remote(args, timeout=900)


def download(root, relative):
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", WORKER,
        "sudo", "-n", "tar", "--exclude=private", "--exclude=maintenance", "-czf", "-", "-C", REMOTE, relative],
        capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError(result.stderr.decode())
    archive = root / "archives" / (relative.replace("/", "-") + ".tar.gz")
    archive.parent.mkdir(exist_ok=True)
    archive.write_bytes(result.stdout)
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:gz") as tar:
        for member in tar.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError("Unsafe archive entry: " + member.name)
        tar.extractall(root)


def proof(directory, filename):
    source = directory / filename
    started = now()
    clock = time.monotonic()
    with LEAN_JOBS:
        p = subprocess.run([str(Path.home() / ".elan/bin/lake"), "env", "lean", "--json", str(source)],
                           cwd=ROOT, capture_output=True, text=True, timeout=180)
    (directory / (source.stem + ".jsonl")).write_text(p.stdout)
    (directory / (source.stem + ".stderr.txt")).write_text(p.stderr)
    messages = [json.loads(line) for line in p.stdout.splitlines() if line.startswith("{")]
    errors = [m for m in messages if m.get("severity") == "error"]
    record = {"source": filename, "started_at": started, "ended_at": now(),
              "runtime_seconds": time.monotonic() - clock, "returncode": p.returncode,
              "errors": errors, "source_sha256": sha(source), "input_sha256": sha(directory / "input.json")}
    write_json(directory / (source.stem + "-result.json"), record)
    return record


def typecheck(root, relative):
    folder = root / relative
    target = folder / "lean"
    target.mkdir(exist_ok=False)
    try:
        data = parse_execution(folder / "snapshot/native", folder / "snapshot/processing")
    except Exception as error:
        result = {"status": "import_error", "error": str(error)}
        write_json(target / "result.json", result)
        return result
    data["vpnIndices"] = [data["deviceIds"][d["id"]] for d in data["sourceDevices"] if d["role"] in {"inner", "outer"}]
    data["outerIndices"] = [data["deviceIds"][d["id"]] for d in data["sourceDevices"] if d["role"] == "outer"]
    write_json(target / "input.json", data)
    files = ["SnapshotCompliance.lean", "HeaderCompliance.lean"]
    results = []
    for name in files:
        shutil.copy2(root / "sources" / name, target / name)
        results.append(proof(target, name))
    errors = [e for r in results for e in r["errors"]]
    expected = all("Tactic `native_decide` evaluated that the proposition" in e["data"] and "is false" in e["data"] for e in errors)
    if errors and expected:
        status = "rejected_by_Lean"
    elif all(r["returncode"] == 0 for r in results):
        status = "accepted_by_Lean"
    else:
        status = "typecheck_infrastructure_error"
    result = {"status": status, "proofs": results, "error_count": len(errors)}
    write_json(target / "result.json", result)
    return result


def network(root, profile_path):
    profile = json.loads(profile_path.read_text())
    name = profile["network"]
    control = root / "controls" / name
    if not (control / "lean/result.json").exists():
        event(root, "clean_control_started", network=name)
        command_path = root / "commands" / (name + "-baseline.json")
        prepared = json.loads(command_path.read_text()) if command_path.exists() else remote("baseline", profile_path)
        write_json(command_path, prepared)
        if prepared["returncode"]:
            raise RuntimeError(prepared["stderr"][-4000:])
        download(root, "controls/" + name)
        result = typecheck(root, "controls/" + name)
        if result["status"] != "accepted_by_Lean":
            raise ValueError({"network": name, "control": result})
        event(root, "clean_control_passed", network=name)
    else:
        if json.loads((control / "lean/result.json").read_text())["status"] != "accepted_by_Lean":
            raise ValueError("Refusing to use a failed clean control")
    for case in profile["mutations"]:
        ident = case["case_id"]
        target = root / "cases" / ident
        if (target / "completed.json").exists():
            continue
        event(root, "case_started", network=name, case=ident)
        injected = remote("inject", profile_path, ident)
        write_json(root / "commands" / (ident + "-inject.json"), injected)
        try:
            download(root, "cases/" + ident)
            if injected["returncode"]:
                raise RuntimeError(injected["stderr"][-4000:])
            result = typecheck(root, "cases/" + ident)
            event(root, "typecheck_finished", network=name, case=ident, status=result["status"], errors=result.get("error_count"))
        finally:
            restored = remote("restore", profile_path, ident)
            write_json(root / "commands" / (ident + "-restore.json"), restored)
            download(root, "cases/" + ident)
        if restored["returncode"]:
            raise RuntimeError(restored["stderr"][-4000:])
        write_json(target / "completed.json", {"at": now(), "network": name, "case": ident,
            "requirement": case["requirement"], "status": result["status"], "restored_to_clean": True,
            "interpretation": "ambiguous" if ident == "net-04-MSC-PF-18" else "supported"})
        event(root, "case_completed", network=name, case=ident, status=result["status"])
    event(root, "network_completed", network=name, cases=len(profile["mutations"]))


def initialize(root):
    root.mkdir(parents=True, exist_ok=False)
    (root / "sources").mkdir()
    shutil.copytree(PREVIOUS / "profiles", root / "profiles")
    for name in ["requirements.json", "deployments.json"]:
        shutil.copy2(PREVIOUS / name, root / name)
    sources = [BASE / name for name in ["isolated_worker.py", "run_isolated_theory.py", "worker.py", "mutate.py",
        "rollback.py", "prepare_blind_networks.py", "validate_live.py", "packet_probe.py", "SnapshotCompliance.lean", "HeaderCompliance.lean"]]
    sources += [ROOT / "scripts/construction/evidence" / name for name in ["collect_native_v2.py", "collect_processing.py"]]
    for source in sources:
        shutil.copy2(source, root / "sources" / source.name)
    frozen = sorted((ROOT / "TDN").rglob("*.lean")) + sorted((ROOT / "mcp/tdn_evidence/parsers").glob("*.py")) + sources
    write_json(root / "freeze.json", {"at": now(), "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"],cwd=ROOT,text=True).strip(),
        "hashes": {str(p.relative_to(ROOT)): sha(p) for p in frozen},
        "scope": "Existing data-plane stack and protocol/multicast proof applications. No new requirement checks added.",
        "sequence": "clean control -> one mutation -> live check -> fresh snapshot -> import -> Lean -> restore; serial per network",
        "concurrency": "Five independent networks may run in parallel; each has at most one injected case active.",
        "post_run": "Leave networks in their checked clean configurations."})
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as tar:
        tar.add(root / "sources", arcname="sources")
        tar.add(root / "profiles", arcname="profiles")
    setup = run_remote(["sudo", "-n", "mkdir", "-m", "700", REMOTE])
    if setup["returncode"]:
        raise RuntimeError(setup)
    uploaded = run_remote(["sudo", "-n", "tar", "-xzf", "-", "-C", REMOTE], input_bytes=data.getvalue())
    if uploaded["returncode"]:
        raise RuntimeError(uploaded)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--network")
    args = p.parse_args()
    root = BASE / "runs" / RUN_ID
    if not args.resume:
        initialize(root)
    profiles = sorted((root / "profiles").glob("net-*.json"))
    if args.network:
        profiles = [x for x in profiles if x.stem == args.network]
    failures = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        jobs = {pool.submit(network, root, path): path for path in profiles}
        for future in as_completed(jobs):
            try:
                future.result()
            except Exception as error:
                failure = {"network": jobs[future].stem, "error": str(error)}
                failures.append(failure)
                event(root, "network_failed", **failure)
    write_json(root / "driver-result.json", {"at": now(), "failures": failures})
    raise SystemExit(bool(failures))
