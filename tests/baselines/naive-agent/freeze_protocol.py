"""Record the exact sources and clean checks used by the active benchmark."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

from cohort import REVISION, require_current_run
from blind_audit import DISABLED, MODELS, PROMPT
from observe_controls import HERE, NETWORKS


ROOT = HERE.parents[2]
PROGRAMS = (
    "clause_scope.json", "clause_branches.json", "cohort.py", "score_trials.py", "run_series.py",
    "MscArchitectureChecks.lean", "architecture_cases.py", "observed_profile.py", "architecture_worker.py",
    "run_architecture_trial.py", "run_case.py", "replicas.py", "register_controls.py", "review_trial.py",
    "delivery_lab.py", "local_packet_probe.py", "link_parking_worker.py", "unplug_lab.py", "peer_lab.py",
    "run_mode_trial.py", "run_delivery_trial.py", "run_unplug_trial.py", "restore_health.py", "observe_controls.py",
    "capture_stable.py", "audit_observations.py", "snapshot_inputs.py", "snapshot_reader.py",
    "ModeChecks.lean",
    "AttachmentChecks.lean",
    "TopologyChecks.lean",
    "SnapshotCompliance.lean",
    "HeaderCompliance.lean",
    "FirewallChecks.lean",
    "reader.py",
    "measure.py",
    "full_suite.py",
    "attachment_view.py",
    "capture_live.py",
    "mode_lab.py",
    "blind_audit.py",
    "supervisor_transport.py",
    "perimeter/run.py",
    "perimeter/approved-control-policy.json",
)
REPO_INPUTS = (
    "data/extraction/source/CSfC_documentation_v1.3.0.pdf",
    "specs/requirement_formalizations.md",
    "specs/requirement_clause_map.json",
    "lean-toolchain",
    "lake-manifest.json",
    "scripts/construction/evidence/collect_native_v2.py",
    "scripts/construction/evidence/collect_processing.py",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def source_rows():
    guide = read(ROOT / "specs/requirement_clause_map.json")
    scope = read(HERE / "clause_scope.json")
    ids = set()
    for group, record in guide.items():
        for index, clause in enumerate(record["clauses"], 1):
            clause_id = f"{group}.{index:02d}"
            row = scope[clause_id]
            assert row["sources"] == clause["sources"], clause_id
            assert row["interpretation"] == clause["interpretation"], clause_id
            assert set(row["scope"]) == set(NETWORKS), clause_id
            ids.add(clause_id)
    if ids != scope.keys():
        raise ValueError("The scope and source clause inventories differ")
    return len(ids)


def manifest(run):
    require_current_run(run)
    paths = [*(ROOT / p for p in REPO_INPUTS), *(HERE / p for p in PROGRAMS)]
    paths.extend(HERE / "profiles" / f"{n}.json" for n in NETWORKS)
    paths.extend((ROOT / "TDN").rglob("*.lean"))
    paths.extend((ROOT / "mcp/tdn_evidence/parsers").rglob("*.py"))
    files = {p.relative_to(ROOT).as_posix(): digest(p) for p in sorted(set(paths))}
    controls = {}
    for n in NETWORKS:
        checks = read(run / "controls" / (n + "-frozen") / "summary.json")
        for key, suffix in [("modes", "-modes"), ("attachments", "-attachments")]:
            checks[key] = read(run / "controls" / (n + suffix) / "result.json")
        if set(checks) != {"modes","attachments","topology","architecture","forwarding","headers","firewall"} or any(v["status"] != "pass" for v in checks.values()):
            raise ValueError(
                "Every fixed check must have a passing clean control for " + n
            )
        controls[n] = {
            k: {
                "source_sha256": v["source_sha256"],
                "evidence_sha256": v["evidence_sha256"],
            }
            for k, v in checks.items()
        }
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "git_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "working_tree_files_sha256": files,
        "lean": (ROOT / "lean-toolchain").read_text().strip(),
        "detector_cli": subprocess.check_output(
            ["codex", "--version"], text=True
        ).strip(),
        "revision": REVISION,
        "original_profiles": list(NETWORKS),
        "source_clause_rows": source_rows(),
        "models": MODELS,
        "reasoning_effort": "high",
        "prompt": PROMPT,
        "reader_operations": ["document", "networks", "observe"],
        "disabled_tools": list(DISABLED),
        "strict_type_success": "A supported common fault type scores as detected only when the affected network and fault are identified in each active network’s independent trial.",
        "independent_scope": "Network applicability comes from the supplied profile. Unselected mechanisms, uncertain authority choices and missing tests have separate statuses.",
        "clean_proofs": controls,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    current = manifest(args.run)
    target = args.run / "protocol.json"
    if target.exists():
        saved = read(target)
        for name in current.keys() - {"captured_at"}:
            if current[name] != saved[name]:
                raise SystemExit("The experimental inputs changed: " + name)
    else:
        with target.open("x") as file:
            file.write(json.dumps(current, indent=2, ensure_ascii=False) + "\n")
    print(
        f"{current['source_clause_rows']} clause rows, {len(current['working_tree_files_sha256'])} source files, {len(NETWORKS)} clean controls"
    )


if __name__ == "__main__":
    main()
