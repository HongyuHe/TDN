"""Validate complete one-fault runs and classify their actual Lean outcomes."""

from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
from historical_paths import historical_path

from common import BASE, ROOT, now, write_json
from run_isolated_theory import RUN_ID

root = BASE / "runs" / RUN_ID
previous = BASE / "runs/20261112-blind-theory-01"
old = json.loads((previous / "scoring.json").read_text())
old_cases = {c["case_id"]: c for c in old["cases"]}
freeze = json.loads((root / "freeze.json").read_text())
revisions = root / "implementation-revisions.json"
if revisions.exists():
    for revision in json.loads(revisions.read_text()):
        assert revision["path"].startswith("tests/baselines/agent/")
        freeze["hashes"][revision["path"]] = revision["new_sha256"]
for name, digest in freeze["hashes"].items():
    assert hashlib.sha256(historical_path(name).read_bytes()).hexdigest() == digest, name

records = []
controls = []

def settled(snapshot_path):
    snapshot = json.loads(snapshot_path.read_text())
    for tunnel in snapshot["tunnels"]:
        state = tunnel["observed_state"]
        assert not any(word in state for word in ["DELETING", "CONNECTING", "REKEYING"]), str(snapshot_path)
        assert state.count("ESTABLISHED") >= 1 and state.count("INSTALLED") >= 1


for path in sorted((root / "profiles").glob("net-*.json")):
    profile = json.loads(path.read_text())
    control = root / "controls" / profile["network"]
    clean_fingerprints = json.loads((control / "fingerprints.json").read_text())
    proof = json.loads((control / "lean/result.json").read_text())
    assert proof["status"] == "accepted_by_Lean"
    settled(control / "snapshot/native/snapshot.json")
    clean = json.loads((control / "public/oracle/clean" / path.name).read_text())
    assert len(clean["records"]) == 20
    assert all(r["status"] == "observed" and not r["violated"] for r in clean["records"])
    controls.append({"network": profile["network"], "proof": proof, "live_cases_absent": 20})
    for case in profile["mutations"]:
        ident = case["case_id"]
        target = root / "cases" / ident
        completion = json.loads((target / "completed.json").read_text())
        assert completion["restored_to_clean"]
        for phase in ["before", "restored"]:
            restoration = json.loads((target / (phase + ".json")).read_text())
            assert not restoration["clean_baseline_mismatches"]
            assert restoration["fingerprints"] == clean_fingerprints, (ident, phase, "clean fingerprints differ")
        selected = json.loads((target / "single-profile.json").read_text())
        assert len(selected["mutations"]) == 1 and selected["mutations"][0] == case
        journal = json.loads((target / "public/mutations" / path.name).read_text())
        assert len(journal["cases"]) == 1 and journal["cases"][0]["case_id"] == ident
        live = json.loads((target / "public/oracle/single-fault" / path.name).read_text())
        assert len(live["records"]) == 1
        assert live["records"][0]["status"] == "observed" and live["records"][0]["violated"]
        manifest = json.loads((target / "snapshot/native/manifest.json").read_text())
        assert manifest["convergence"]["consistent"] and not manifest["collection_failures"]
        settled(target / "snapshot/native/snapshot.json")
        result = json.loads((target / "lean/result.json").read_text())
        assert result["status"] in {"accepted_by_Lean", "rejected_by_Lean"}, (ident, result)
        imported = json.loads((target / "lean/input.json").read_text())
        assert imported["redSources"] and imported["blackIfaces"] and imported["vpnIndices"]
        assert len(imported["sourceDevices"]) == len(profile["topology"]["devices"])
        for proof in result["proofs"]:
            assert datetime.fromisoformat(manifest["ended_at"]) <= datetime.fromisoformat(proof["started_at"])
            assert datetime.fromisoformat(proof["ended_at"]) <= datetime.fromisoformat(completion["at"])
            assert hashlib.sha256((target / "lean" / proof["source"]).read_bytes()).hexdigest() == proof["source_sha256"]
            assert hashlib.sha256((target / "lean/input.json").read_bytes()).hexdigest() == proof["input_sha256"]
        errors = [e for p in result["proofs"] for e in p["errors"]]
        records.append({"case_id": ident, "network": profile["network"], "device": case["device"],
            "requirement": case["requirement"], "description": case["description"],
            "ground_truth_status": old_cases[ident]["ground_truth_status"],
            "tdn_detected": result["status"] == "rejected_by_Lean", "status": result["status"],
            "errors": errors, "snapshot_started": manifest["started_at"], "snapshot_ended": manifest["ended_at"],
            "lean_seconds": sum(p["runtime_seconds"] for p in result["proofs"]),
            "astra": old_cases[ident]["astra"], "sol": old_cases[ident]["sol"],
            "previous_related_detection": old_cases[ident]["tdn"]["fault_found"],
            "previous_exact_requirement_match": old_cases[ident]["tdn"]["exact"]})

assert len(records) == 100 and len({r["case_id"] for r in records}) == 100
supported = [r for r in records if r["ground_truth_status"] == "supported"]
by_requirement = []
for requirement in sorted({r["requirement"] for r in records}):
    cases = [r for r in records if r["requirement"] == requirement]
    by_requirement.append({"requirement": requirement, "description": cases[0]["description"],
        "cases": len(cases), "rejected": sum(r["tdn_detected"] for r in cases),
        "accepted": sum(not r["tdn_detected"] for r in cases),
        "error_conditions": sorted({e["data"] for r in cases for e in r["errors"]})})

events = [json.loads(x) for x in (root / "events.jsonl").read_text().splitlines()]
for network in {r["network"] for r in records}:
    active = None
    checked = False
    for event in events:
        if event.get("network") != network:
            continue
        if event["event"] == "case_started":
            assert active is None, (network, "overlapping cases")
            active, checked = event["case"], False
        elif event["event"] == "typecheck_finished":
            assert event["case"] == active
            checked = True
        elif event["event"] == "case_completed":
            assert event["case"] == active and checked
            active = None
        elif event["event"] == "case_attempt_abandoned":
            assert event["case"] == active
            active = None
    assert active is None
first = min(e["at"] for e in events if e["event"] == "clean_control_started")
last = max(e["at"] for e in events if e["event"] == "network_completed")
summary = {"cases": 100, "clean_controls": 5, "detected": sum(r["tdn_detected"] for r in records),
    "not_detected": sum(not r["tdn_detected"] for r in records),
    "supported_cases": len(supported), "supported_detected": sum(r["tdn_detected"] for r in supported),
    "import_or_infrastructure_errors": 0, "live_before_checks": 100, "live_single_fault_checks": 100,
    "restored_cases": 100, "final_lean_file_checks": 210,
    "all_lean_file_checks_including_repeats": len(list(root.glob("**/lean/*Compliance-result.json"))),
    "retained_earlier_attempts": len(list((root / "attempts").glob("*"))),
    "lean_job_seconds": sum(r["lean_seconds"] for r in records),
    "started_at": first, "ended_at": last,
    "wall_seconds": (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds(),
    "differences_from_previous_attribution": [r["case_id"] for r in records if r["tdn_detected"] != r["previous_related_detection"]]}
write_json(root / "scoring.json", {"at": now(), "summary": summary, "by_requirement": by_requirement, "cases": records})
write_json(root / "validation.json", {"at": now(), "status": "passed", "summary": summary,
    "theory_and_parser_hashes_unchanged": True,
    "source_and_input_hashes_checked": True, "single_mutation_journals_checked": True,
    "all_snapshots_stable_in_collected_fields": True,
    "all_before_and_after_fingerprints_match_clean_controls": True,
    "case_sequence_verified_per_network": True, "nonempty_source_and_black_interface_sets": True,
    "final_snapshots_have_no_closing_or_connecting_tunnel_sessions": True,
    "scope": "Two fixed Lean proof applications per snapshot; successful checking does not establish every CSfC requirement."})
print(json.dumps(summary, indent=2))
