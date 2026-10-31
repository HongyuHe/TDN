"""Render the revised stopping assessment from explicit reviewed requirement-clause records."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def preserve(path):
    if path.exists():
        prior = path.read_bytes()
        folder = RUN / "assessment-revisions"
        folder.mkdir(exist_ok=True)
        (folder / (hashlib.sha256(prior).hexdigest() + "-" + path.name)).write_bytes(prior)


def main():
    register_path = RUN / "theorem_register.json"
    register = json.loads(register_path.read_text())
    review = json.loads((RUN / "practical-provability-review.json").read_text())
    rows = []
    for group in register["groups"]:
        gid = group["group_id"]
        item = review[gid]
        rows.append({"group_id": gid, "title": group["title"], **item,
                     "stronger_unfinished_work": group.get("remaining_construction_work", []) +
                         group.get("other_case_application_work", []),
                     "source_passages": [c["source_id"] for c in group["clause_progress"]]})
    counts = {}
    for row in rows:
        status = row["classification"]
        counts[status] = counts.get(status, 0) + 1
    pending = [r["group_id"] for r in rows if r["classification"] in
               {"practical_positive_partial_pending", "unresolved_review"}]
    result = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "stopping_condition": "Every RG practically provable with available evidence and current emulations has at least one meaningful positive partial proof, with a reusable general result and checked concrete evidence.",
        "counting_rule": "Actual requirement clauses only. Definitions, context, vacuous checks, negative diagnostics, and unfulfilled conditional results do not count.",
        "scope_note": "A positive partial result does not establish the encompassing RG or all representative cases. Stronger unfinished work is retained separately.",
        "register_sha256": hashlib.sha256(register_path.read_bytes()).hexdigest(),
        "counts": counts, "groups": rows, "pending_groups": pending,
        "may_stop_under_revised_condition": not pending and all(
            r.get("review_complete", False) for r in rows),
        "all_76_fully_established": False,
        "final_validation_required": "The classification threshold is separate from final build, proof-body dependency audit and coordinator acceptance.",
        "cross_accounting": {application: [r["group_id"] for r in rows if r.get("application") == application]
            for application in {r.get("application") for r in rows if r.get("application")}
            if sum(r.get("application") == application for r in rows) > 1}}
    for name in ["practical-provability.json", "practical-provability.md"]:
        preserve(RUN / name)
    (RUN / "practical-provability.json").write_text(json.dumps(result, indent=2) + "\n")
    lines = ["# Practical proof coverage under the revised stopping condition", "",
             result["stopping_condition"], "", result["counting_rule"], "",
             result["scope_note"], "",
             "Current classification: " + ", ".join(f"{key}: {value}" for key, value in counts.items()) + ".",
             "", "Stopping is permitted: " + str(result["may_stop_under_revised_condition"]).lower() + ".", ""]
    for row in rows:
        lines.extend(["## " + row["group_id"] + ": " + row["title"], "",
                      "**" + row["classification"] + ".** " + row["reason"], "",
                      "Clause and scope: " + row.get("clause", "Review pending.")])
        for key, label in [("selected_source_ids", "Selected original source passages"), ("general", "General proof"), ("application", "Checked application"),
                           ("evidence", "Evidence"), ("next_action", "Next action")]:
            if row.get(key):
                value = row[key]
                lines.append(label + ": " + (", ".join(value) if isinstance(value, list) else value))
        lines.append("")
    (RUN / "practical-provability.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({"counts": counts, "pending": pending, "may_stop": result["may_stop_under_revised_condition"]}))


if __name__ == "__main__":
    main()
