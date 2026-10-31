"""Apply a complete reviewed source-role inventory without claiming theorem completion."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from validate_evidence import require

NON_OBLIGATIONS = {
    "context", "future-policy-context", "applicability-permission", "requirement-interpretation-rule",
    "recommendation", "organizational-recommendation", "recommendation-and-alternative-rule",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("review")
    args = parser.parse_args()
    review_path = Path(args.review)
    review = json.loads(review_path.read_text())
    run = Path(os.environ["TDN_OUTPUT_DIR"])
    path = run / "theorem_register.json"
    register = json.loads(path.read_text())
    group = next(g for g in register["groups"] if g["group_id"] == review["group_id"])
    source = {p["source_id"]: p["text"] for p in group["source_passages"]}
    rows = {r["source_id"]: r for r in review["records"]}
    require(len(rows) == len(review["records"]) and set(rows) == set(source), "Incomplete reviewed source inventory")
    require(all(source[sid] == row["original_text"] for sid, row in rows.items()), "Reviewed source text differs")
    for context in review["source_contexts"]:
        require(hashlib.sha256(Path(context["path"]).read_bytes()).hexdigest() == context["sha256"],
                "Reviewed original context hash differs")
    prior = path.read_bytes()
    revisions = run / "register-revisions"
    revisions.mkdir(exist_ok=True)
    (revisions / (hashlib.sha256(prior).hexdigest() + ".json")).write_bytes(prior)
    for clause in group["clause_progress"]:
        row = rows[clause["source_id"]]
        role = row["reviewed_role"]
        status = "context_only" if role in NON_OBLIGATIONS else "construction_in_progress"
        if "recommendation" in role:
            status = "recommendation"
        if role == "split-partial-general-and-open-application":
            status = "partial_general_result"
        clause.update(status=status, reason=row["reason"], reviewed_role=role,
                      source_review=str(review_path),
                      current_relevant_declarations=row["current_relevant_declarations"],
                      remaining_work=row["remaining_work"])
    for unit in group["source_clause_records"]:
        selected = [rows[sid] for sid in unit["source_passage_ids"]]
        unit["reviewed_subclauses"] = selected
        unit["decomposition_complete"] = True
        unit["source_review"] = str(review_path)
        unit["status"] = "source_roles_reviewed_with_open_obligations" if any(
            r["reviewed_role"] not in NON_OBLIGATIONS for r in selected) else "context_or_interpretation_accounted"
        unit["completion_claim"] = False
    group["remaining_construction_work"] = list(dict.fromkeys(
        task for row in review["records"] for task in row["remaining_work"]))
    group["remaining_construction_work"].append(
        "Assemble aggregate CP compliance only after every selected applicable clause has its own checked application; successful examples and context classification do not discharge aggregate compliance.")
    group["status"] = "construction_in_progress"
    group["disposition_reason"] = (
        "All source passages have individual roles reviewed against original context. Technical capability, CNSS policy application, effective-policy precedence and aggregate compliance remain explicit tasks.")
    group["source_role_review"] = str(review_path)
    path.write_text(json.dumps(register, indent=2) + "\n")
    print(json.dumps({"group": group["group_id"], "reviewed_passages": len(rows),
                      "non_obligation_passages": sum(r["reviewed_role"] in NON_OBLIGATIONS for r in rows.values()),
                      "completion_claim": False}))


if __name__ == "__main__":
    main()
