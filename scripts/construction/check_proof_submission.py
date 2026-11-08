"""Check a proof submission's inventory and compiled dependency metadata."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def declarations(document):
    return {row["name"]: row for row in document["declarations"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--accepted-map", required=True)
    parser.add_argument("--proof-map", required=True)
    parser.add_argument("--accepted-definitions", required=True)
    parser.add_argument("--candidate-definitions", required=True)
    parser.add_argument("--compiled-audit", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--groups", nargs="+", help="Review only these completed RGs; default: all 24.")
    args = parser.parse_args()
    accepted = load(args.accepted_map)
    proof_map = load(args.proof_map)
    if isinstance(accepted, dict):
        accepted = accepted["groups"]
    catalog = {row["rg_id"]: row for row in accepted}
    selected = set(args.groups) if args.groups else set(catalog)
    if len(catalog) != 24 or not selected or not selected <= set(catalog):
        parser.error("Select known RGs from the complete 24-group accepted map.")
    expected = {key: value for key, value in catalog.items() if key in selected}
    supplied = {row["rg_id"]: row for row in proof_map}
    failures = []
    if len(proof_map) != len(expected) or set(supplied) != set(expected):
        failures.append("The submitted map must contain exactly the selected accepted RGs.")
    audit = load(args.compiled_audit)
    audited_roots = {row["name"]: row for row in audit["roots"]}
    compiled = declarations(audit)
    prior = declarations(load(args.accepted_definitions))
    current = declarations(load(args.candidate_definitions))
    removed = sorted(set(prior) - set(current))
    changed = []
    for name in sorted(set(prior) & set(current)):
        compared = ["kind", "type", "body"]
        compared.extend(field for field in ["type_expression", "body_expression"] if field in prior[name])
        fields = [field for field in compared if prior[name].get(field) != current[name].get(field)]
        if fields:
            changed.append({"name": name, "changed_fields": fields})
    if removed or changed:
        failures.append("Accepted compiled specification definitions changed; supervisor meaning review is required.")
    if audit["unexpected_axiom_roots"]:
        failures.append("The compiled audit reports unexpected axioms.")
    results = []
    for rg_id, row in supplied.items():
        name = row.get("general_theorem")
        expected_spec = expected.get(rg_id, {}).get("specification")
        if row.get("accepted_specification") != expected_spec:
            failures.append(rg_id + ": accepted specification mapping differs.")
        if not name or name not in audited_roots:
            failures.append(rg_id + ": general theorem is missing from the compiled audit.")
            continue
        pending = [name]
        seen = set()
        evidence_dependencies = []
        while pending:
            dependency = pending.pop()
            if dependency in seen:
                continue
            seen.add(dependency)
            declaration = compiled.get(dependency)
            if declaration is None:
                if dependency.startswith(("TDN.", "_private.TDN.")):
                    failures.append(rg_id + ": missing TDN dependency metadata: " + dependency)
                continue
            module = declaration.get("module")
            if module is None:
                failures.append(rg_id + ": missing defining module for " + dependency)
            elif module.startswith("TDN.Evidence"):
                evidence_dependencies.append({"name": dependency, "module": module})
            pending.extend(declaration["type_dependencies"] + declaration["body_dependencies"])
        if evidence_dependencies:
            failures.append(rg_id + ": general theorem depends on concrete evidence modules.")
        root = audited_roots[name]
        results.append({"rg_id": rg_id, "specification": expected_spec, "general_theorem": name,
                        "conclusion_head": root.get("conclusion_head"), "conclusion": root["conclusion"],
                        "assumptions": root["binders"], "axioms": root["axioms"],
                        "evidence_dependencies": evidence_dependencies,
                        "compiled_dependency_count": len(seen),
                        "conclusion_head_matches_without_unfolding": root.get("conclusion_head") == expected_spec})
    report = {"at": datetime.now(timezone.utc).isoformat(),
              "scope": "Structural audit only. Supervisor must inspect clause coverage, assumptions, applicability and meaningful applications.",
              "selected_groups": sorted(selected),
              "input_sha256": {key: digest(value) for key, value in vars(args).items() if key not in ["output", "groups"]},
              "exact_expression_comparison": all("type_expression" in row and "body_expression" in row
                                                 for row in prior.values()),
              "failures": failures, "accepted_definitions_removed": removed,
              "accepted_definitions_changed": changed, "results": results}
    with Path(args.output).open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"targets": len(results), "failures": len(failures), "output": args.output}))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
