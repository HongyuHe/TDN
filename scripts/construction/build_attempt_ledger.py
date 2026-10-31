"""Distinguish actual scoped proof work from unassigned clause-level attempts."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def preserved_write(path, data):
    if path.exists():
        previous = path.read_bytes()
        revision = RUN / "assessment-revisions"
        revision.mkdir(exist_ok=True)
        (revision / (hashlib.sha256(previous).hexdigest() + "-" + path.name)).write_bytes(previous)
    path.write_text(data)


def main():
    register = json.loads((RUN / "theorem_register.json").read_text())
    mapping = {g["group_id"]: g for g in json.loads((RUN / "current_declaration_map.json").read_text())}
    attempts = []
    for path in sorted((RUN / "experiments").glob("*.attempt.json")):
        data = json.loads(path.read_text())
        attempts.append({"record": str(path), "command": data["command"], "exit_code": data["exit_code"],
                         "source_checkpoint": data["source_checkpoint"], "log": data["log"]})
    groups = []
    counts = Counter()
    for group in register["groups"]:
        mapped = mapping[group["group_id"]]
        results = mapped["general_and_supporting_results"] + mapped["checked_applications"]
        declaration_names = {r["name"] for r in results}
        paths = {loc["path"] for row in results for loc in
                 ([row["location"]] if row.get("location") else row.get("locations", []))}
        modules = {path.removesuffix(".lean").replace("/", ".") for path in paths}
        targeted = [attempt for attempt in attempts if any(
            arg in paths or arg in modules for arg in attempt["command"])]
        progress = {row["source_id"]: row for row in group["clause_progress"]}
        units = []
        for unit in group.get("source_clause_records", []):
            passages = [progress[sid] for sid in unit["source_passage_ids"]]
            exact_results = unit.get("exact_clause_result", [])
            exact_names = sorted({name for row in exact_results for name in
                                  row.get("current_scoped_applications", []) + row.get("lean_theorems", [])})
            reviewed = unit.get("reviewed_subclauses", [])
            declared = sorted({name for row in reviewed for name in row.get("current_relevant_declarations", [])})
            no_obligation = all(row["status"] in {"context_only", "recommendation"} for row in passages)
            if no_obligation:
                disposition = "context_or_interpretation_accounted"
            elif exact_names:
                disposition = "explicit_scoped_clause_result_recorded"
            elif declared:
                disposition = "source_review_names_general_contribution"
            elif results:
                disposition = "group_work_exists_exact_clause_attempt_unassigned"
            else:
                disposition = "no_clause_attempt_assigned_in_current_register"
            counts[disposition] += 1
            specific = list(dict.fromkeys(task for row in reviewed for task in row.get("remaining_work", [])))
            units.append({
                "source_unit_id": unit["source_unit_id"], "clause_id": unit.get("clause_id"),
                "source_passage_ids": unit["source_passage_ids"], "source_text": unit["original_text"],
                "record_kind": unit["record_kind"], "attempt_disposition": disposition,
                "explicit_clause_result_records": exact_results, "explicit_clause_declarations": exact_names,
                "reviewed_general_contributions": declared,
                "mapped_names_present": {name: name in declaration_names for name in exact_names},
                "reviewed_subclauses": reviewed, "specific_remaining_tasks": specific,
                "attempt_assignment_action": None if no_obligation or exact_names else
                    "Identify the exact source clause, construct or identify its supporting proof, bind relevant retained evidence, and record the command/result for that clause. A group-wide build does not perform that assignment.",
                "inherited_passage_dispositions": [{"source_id": row["source_id"], "status": row["status"],
                    "reason": row.get("reason", "")} for row in passages],
                "provisional_limits_accepted_as_final": False,
                "mathematical_unprovability_claimed": False,
            })
        groups.append({
            "group_id": group["group_id"], "title": group["title"],
            "specification": mapped["specification"],
            "general_and_supporting_results": mapped["general_and_supporting_results"],
            "scoped_applications": mapped["checked_applications"],
            "targeted_module_attempts": targeted,
            "targeted_attempt_scope_note": "These commands target modules containing mapped results. The search is not an exhaustive failed-proof history. Missing assignments do not establish that no attempt occurred, and module commands do not establish attempts on every clause.",
            "selected_specification_certificate": group.get("completion_certificate"),
            "group_specific_work_queue": list(dict.fromkeys(group.get("remaining_construction_work", []) +
                                                           group.get("other_case_application_work", []))),
            "source_units": units,
            "full_clause_attempt_coverage_established": False,
            "attempt_coverage_basis": "A separate exhaustive reconstructed-obligation audit is not yet supplied. One result for a source unit cannot establish attempts for all of its clauses.",
            "final_group_exclusion": False,
        })
    result = {"at": datetime.now(timezone.utc).isoformat(), "groups": groups,
              "group_count": len(groups), "source_passages": sum(len(g["source_passages"]) for g in register["groups"]),
              "source_units": sum(len(g["source_units"]) for g in groups),
              "unit_dispositions": dict(counts), "all_clause_attempts_completed": False,
              "whole_builds_count_as_all_group_attempts": False,
              "final_excluded_groups": [], "may_stop": False,
              "limits": [
                  "Source units may contain several requirements or only context. Their count is not an obligation count.",
                  "An unassigned clause may have useful work in a mapped module. Its exact claim-to-source connection is not yet evidenced in this ledger.",
                  "A scoped result does not establish every alternative or every clause in its source unit.",
                  "Prior unavailable-evidence and interpretation labels remain provisional unless separately reviewed at the clause level.",
              ]}
    preserved_write(RUN / "attempt-ledger-all76.json", json.dumps(result, indent=2) + "\n")
    lines = ["# All-76 proof-attempt ledger", "",
             "All 76 specifications exist. Systematic proof-attempt coverage of every applicable clause is still incomplete. No group has been finally excluded as mathematically unprovable.", "",
             "The ledger records authored general results, scoped applications, targeted module commands and exact source-clause assignments separately. Repeated whole builds do not count as attempts on all 76 groups.", "",
             "There are " + str(result["source_units"]) + " reconstructed source units covering 749 passages. A unit may contain several obligations or only context. Counts below describe accounting records.", "",
             "| Record disposition | Units |", "| --- | ---: |"]
    lines.extend("| " + key.replace("_", " ") + " | " + str(value) + " |" for key,value in counts.items())
    for group in groups:
        lines += ["", "## " + group["group_id"] + ": " + group["title"], "",
                  "Mapped general/supporting results: " + str(len(group["general_and_supporting_results"])) +
                  ". Scoped applications: " + str(len(group["scoped_applications"])) +
                  ". Targeted module attempts: " + str(len(group["targeted_module_attempts"])) + ".", "",
                  "Exact source-unit dispositions:", ""]
        for unit in group["source_units"]:
            label = unit["clause_id"] or unit["source_unit_id"]
            lines.append("- " + label + ": " + unit["attempt_disposition"].replace("_", " ") + ".")
            if unit["explicit_clause_declarations"]:
                lines.append("  Recorded declarations: " + ", ".join(unit["explicit_clause_declarations"]) + ".")
            if unit["specific_remaining_tasks"]:
                lines.extend("  Remaining: " + task for task in unit["specific_remaining_tasks"])
        lines += ["", "Current concrete group queue:", ""]
        lines.extend("- " + task for task in group["group_specific_work_queue"])
    preserved_write(RUN / "attempt-ledger-all76.md", "\n".join(lines) + "\n")
    print(json.dumps({key: result[key] for key in ["group_count", "source_units", "unit_dispositions",
                                                  "all_clause_attempts_completed", "final_excluded_groups"]}))


if __name__ == "__main__":
    main()
