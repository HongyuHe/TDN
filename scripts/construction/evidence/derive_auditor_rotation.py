"""Recover the recorded Auditor rotation from HTTP responses and retained log files."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from import_service_authorization import parse_authorization, validate_public_bundle, require


def canonical(event):
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


def derive(base):
    base = Path(base)
    deployment = base / "role-admin-deploy-v4"
    effective = base / "role-admin-effective-v3"
    matrix_path = base / "role-admin-matrix-v3"
    auth = parse_authorization(deployment, effective, matrix_path)
    matrix = validate_public_bundle(matrix_path)["records"]
    runtime = validate_public_bundle(effective)["records"]
    fingerprint = auth["certificates"]["auditor"]
    selections = {}
    for index, row in enumerate(matrix):
        c = row["command"]
        if c[0] != "curl" or "--cert" not in c or "--head" in c:
            continue
        if Path(c[c.index("--cert") + 1]).stem != "auditor":
            continue
        url = next((v for v in c if v.startswith("https://managed.nd.test:8443/")), None)
        if url is None:
            continue
        path = url.removeprefix("https://managed.nd.test:8443")
        if path in {"/audit", "/filter", "/audit/rotate"}:
            require(path not in selections, "Duplicate selected Auditor operation")
            require(row["returncode"] == 0, "Auditor HTTP command failed")
            body, status = row["stdout"].rsplit("\nHTTP_STATUS=", 1)
            selections[path] = {"index": index, "at": row["at"], "body": json.loads(body), "status": int(status)}
    read, denied, rotated = [selections[p] for p in ["/audit", "/filter", "/audit/rotate"]]
    require(read["status"] == rotated["status"] == 200 and denied["status"] == 403,
            "Unexpected selected Auditor outcome")
    require(read["index"] < denied["index"] < rotated["index"], "Auditor operation order changed")
    files = {}
    for row in runtime:
        c = row["command"]
        if c[:4] == ["docker", "exec", "ND_O_A1", "cat"] and c[-1].endswith(".jsonl"):
            require(row["returncode"] == 0 and not row["stderr"], "Audit file read failed")
            files[Path(c[-1]).name] = [json.loads(line) for line in row["stdout"].splitlines()]
    require(set(files) == {"audit-0001.jsonl", "audit-0002.jsonl", "audit.jsonl"}, "Selected archive inventory differs")
    require(rotated["body"]["rotation"] == 2, "Wrong archived generation")
    previous = files["audit-0001.jsonl"]
    moved = files["audit-0002.jsonl"]
    active = files["audit.jsonl"]
    before_read = read["body"]["events"]
    require(len(previous) == 3 and len(before_read) == 8 and len(moved) == 7 and active,
            "Unexpected selected observation coverage")
    require(previous + moved[:5] == before_read, "Archived bytes differ from earlier Auditor readback")
    appended = moved[5:]
    require([(r["role"], r["fingerprint"], r["method"], r["path"], r["status"]) for r in appended] == [
        ("Auditor", fingerprint, "GET", "/audit", 200),
        ("Auditor", fingerprint, "POST", "/filter", 403)], "Intervening records differ")
    operation = active[0]
    require((operation["role"], operation["fingerprint"], operation["method"], operation["path"], operation["status"]) ==
            ("Auditor", fingerprint, "POST", "/audit/rotate", 200), "Rotation was not performed by the recorded Auditor")
    require(rotated["body"]["retained_events"] == len(previous) + len(moved), "Reported retained count differs")
    all_events = previous + moved + active
    require(all(datetime.fromisoformat(a["at"]) < datetime.fromisoformat(b["at"])
                for a, b in zip(all_events, all_events[1:])), "Audit chronology changed")
    require(datetime.fromisoformat(operation["at"]) <= datetime.fromisoformat(rotated["at"]),
            "Rotation result predates the recorded operation")
    return {
        "component": "ND_O_A1", "authenticated_role": "Auditor", "certificate_fingerprint": fingerprint,
        "source_sha256": auth["source_sha256"],
        "before_read": list(map(canonical, before_read)),
        "before_archives": [list(map(canonical, previous))],
        "before_active": list(map(canonical, moved)),
        "intervening_events_after_read": list(map(canonical, appended)),
        "operation_record": canonical(operation),
        "after_archives": [list(map(canonical, previous)), list(map(canonical, moved))],
        "after_active": [canonical(operation)],
        "later_observed_active": list(map(canonical, active)),
        "http_observations": selections,
        "input_manifests": [{"path": str(p / "manifest.json"), "sha256": hashlib.sha256((p / "manifest.json").read_bytes()).hexdigest()}
                            for p in [deployment, effective, matrix_path]],
        "interpretation": [
            "The earlier actual Auditor readback contains eight complete records. Those exact records occur in the two later archive files, followed by two known intervening audit events.",
            "before_active is the reconstructed pre-rotation active list, using the earlier eight-record readback, the two intervening operations, the later archive and the pinned sequential service source. It is not a separately captured pre-rotation file.",
            "after_active is the immediate post-rotation prefix inferred from the source order and the first event of the later actual active file. The full later active file is separately retained, including thirteen subsequent events.",
            "The source uses sequential HTTPServer, renames the active file into a fresh archive name, then appends the rotation event. Correct rename/append behavior, a fresh destination, unchanged source/runtime binding and absence of external log mutation during this interval are explicit implementation assumptions.",
            "This proves the selected Auditor log-management contribution in p054:u014.s001. It does not prove human review, incident reports, a System Audit Capability Survey, or component-wide access restrictions."
        ]
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = derive(a.base)
    a.output.mkdir(parents=True)
    out = a.output / "rotation.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    (a.output / "manifest.json").write_text(json.dumps({"files": [{"path": out.name,
        "sha256": hashlib.sha256(out.read_bytes()).hexdigest()}],
        "deriver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}, indent=2) + "\n")
    print(json.dumps({"before_read_records": len(result["before_read"]),
                      "archived_records": sum(map(len, result["after_archives"])),
                      "later_active_records": len(result["later_observed_active"])}))


if __name__ == "__main__":
    main()
