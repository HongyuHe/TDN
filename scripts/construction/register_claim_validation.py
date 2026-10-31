"""Validate completion accounting and emit closed Lean applications for whole claims."""
import re

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*\Z")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def validate_group_claim(group, evidence_catalog):
    require(bool(group.get("disposition_reason")), "Missing group disposition")
    if not group.get("established"):
        require(bool(group.get("remaining_construction_work") or group.get("clause_limitations")),
                "Unfinished group lacks work or a recorded limitation")
        return None
    require(not group.get("remaining_construction_work"), "Completed group retains actionable work")
    require(not group.get("outstanding_assumptions"), "Completed group retains unchecked assumptions")
    spec = group.get("formal_definition", "")
    general = group.get("general_theorem", "")
    require(NAME.fullmatch(spec) and NAME.fullmatch(general), "Missing specification or general theorem")
    clauses = group.get("clause_progress", [])
    require(clauses and all(row["status"] in {"established", "not_applicable", "context_only", "recommendation"}
                           for row in clauses), "Completed group has an unfinished source clause")
    require(any(row["status"] == "established" for row in clauses), "No established requirement clause")
    for clause in clauses:
        if clause["status"] in {"not_applicable", "context_only", "recommendation"}:
            require(bool(clause.get("reason")), "Source exclusion lacks an explanation")
    certificate = group.get("completion_certificate", {})
    require(certificate.get("scope") and certificate.get("implementation_contract"),
            "Completed group lacks scope or implementation contract")
    required = {row["source_id"] for row in clauses if row["status"] == "established"}
    require(set(certificate.get("covered_source_ids", [])) == required,
            "Completion certificate does not cover the exact established source clauses")
    keys = certificate.get("evidence_keys", [])
    require(keys and all(key in evidence_catalog for key in keys), "Completion evidence is missing")
    application = certificate.get("application", {})
    goal = application.get("lean_goal", "")
    proof = application.get("lean_proof", "")
    terms = goal.split()
    require(terms and terms[0] == spec and all(NAME.fullmatch(term) for term in terms),
            "Completion goal must be the registered specification applied only to named definitions")
    require(NAME.fullmatch(proof), "Completion proof must name a closed Lean declaration")
    require(not any(token in goal for token in ["\n", ";", "--", "/-", "by ", "sorry", "axiom"]),
            "Unsupported completion goal syntax")
    require(any(row.get("name") == proof and row.get("whole_group_claim") is True
                for row in group.get("checked_applications", [])),
            "Whole-specification proof is not a mapped complete application")
    require(certificate.get("requirement_premises_checked") is True,
            "A source requirement remains an unchecked premise")
    return "example : " + goal + " := " + proof


def validate_scoped_specification(group, certificate, evidence_catalog):
    spec = group.get("formal_definition", "")
    require(NAME.fullmatch(spec), "Scoped claim lacks a registered specification")
    require(certificate.get("scope") and certificate.get("implementation_contract"),
            "Scoped claim lacks scope or implementation contract")
    require(certificate.get("scope_exclusions") is not None,
            "Scoped claim lacks explicit source-qualification accounting")
    require(certificate.get("requirement_premises_checked") is True,
            "Scoped specification retains unchecked requirement premises")
    keys = certificate.get("evidence_keys", [])
    require(keys and all(key in evidence_catalog for key in keys), "Scoped evidence is missing")
    application = certificate.get("application", {})
    goal, proof = application.get("lean_goal", ""), application.get("lean_proof", "")
    terms = goal.split()
    require(terms and terms[0] == spec and all(NAME.fullmatch(term) for term in terms),
            "Scoped goal must be the registered specification applied only to named definitions")
    require(NAME.fullmatch(proof), "Scoped proof must be a closed declaration")
    require(any(row.get("name") == proof for row in group.get("checked_applications", [])),
            "Scoped proof has no current declaration mapping")
    return "example : " + goal + " := " + proof
