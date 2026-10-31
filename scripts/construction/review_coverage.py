import collections
import hashlib
import json
from pathlib import Path
from source_paths import source_path,output_path
from validate_evidence import require



def current_cases_review(cases, examples, groups, clause_count):
    examples_by_id = {e["example_id"]: e for e in examples}
    counts = {i: 1 for i in range(1, 28)}
    counts.update({8: 2, 11: 4, 15: 2, 16: 2, 17: 3, 19: 2, 20: 3,
                   21: 6, 22: 8, 23: 7, 25: 2, 26: 2, 27: 2})
    expected = {f"NET-{n:03d}": count for n, count in counts.items()}
    actual = dict(collections.Counter(c["example_id"] for c in cases["cases"]))
    require(actual == expected and len(cases["cases"]) == cases["case_count"],
            "Current source-alternative expansion differs")
    require(len({c["coverage_id"] for c in cases["cases"]}) == len(cases["cases"]),
            "Duplicate current case identifier")
    reviewed = []
    for case in cases["cases"]:
        example = examples_by_id[case["example_id"]]
        require(set(case["source_ids"]) <= set(example["source_ids"]),
                "Case source identity outside mapped example")
        require(case["containment_or_case_justification"], "Case containment lacks justification")
        require(case["availability"] in {"present", "unavailable", "pending"}, "Unknown case availability")
        manifests = []
        if case["availability"] == "present":
            require(case["manifest_paths"], "Present case lacks durable manifest")
            for name in case["manifest_paths"]:
                path = Path(name)
                require(path.is_file(), "Published case manifest missing")
                manifests.append({"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        mapped = [row["group_id"] for row in example["requirement_group_mappings"]]
        reviewed.append({"case_id": case["coverage_id"], "example_id": case["example_id"],
            "alternative": case["case"], "availability": case["availability"],
            "representative_scope": case["representative_scope"],
            "source_ids": case["source_ids"], "manifest_bindings": manifests,
            "containment_or_case_justification": case["containment_or_case_justification"],
            "mapped_requirement_groups": mapped,
            "whole_case_compliance_established": all(groups[gid]["established"] and
                any(case["coverage_id"] in app.get("case_ids", []) for app in
                    groups[gid].get("checked_applications", [])) for gid in mapped) if mapped else False})
    report = {"schema_version": "csfc-construction-coverage-review/v2", "groups": len(groups),
        "source_passages_preserved": clause_count, "examples": len(examples),
        "representative_cases": len(reviewed), "case_ledger": str(source_path("case_coverage")),
        "case_ledger_sha256": hashlib.sha256(source_path("case_coverage").read_bytes()).hexdigest(),
        "cases": reviewed, "semantic_review_limit":
        "Source-linked case coverage and durable manifests do not establish whole-case compliance. Each actual application requires its own mapped local checks and source clauses."}
    output_path("coverage-review.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in {"cases", "semantic_review_limit"}}))


def review():
    source=json.loads(Path("artifacts/extraction/requirements/groups.json").read_text())
    register=json.loads(output_path("theorem_register.json").read_text())
    groups={g["group_id"]:g for g in register["groups"]}
    require(len(groups)==len(register["groups"])==76 and set(groups)=={g["group_id"] for g in source["groups"]},"76-group coverage mismatch")
    clause_count=0
    for original in source["groups"]:
        group=groups[original["group_id"]]
        for key,original_key in [("top_level_target","theorem_name"),("original_intended_statement","theorem_statement"),("applicability","applicability"),("source_ids","source_ids"),("source_passages","requirement_passages"),("qualifications_and_exceptions","qualifications_and_exceptions")]:
            require(group[key]==original[original_key],"source fidelity differs: "+group["group_id"]+" "+key)
        require({(c["source_id"],c["text"]) for c in group["clause_progress"]}=={(c["source_id"],c["text"]) for c in original["requirement_passages"]},"clause register omitted/changed source text")
        require(group["disposition_reason"], "target disposition missing")
        if group["established"]:
            require(group["formal_definition"] and group.get("general_theorem"), "completed target lacks specification/general theorem")
            require(group.get("checked_applications"), "completed target lacks checked applications")
            require(not group["remaining_construction_work"], "completed target has remaining construction work")
            require(all(c["status"] in {"established", "not_applicable", "context_only", "recommendation"} for c in group["clause_progress"]), "completed target has unfinished clauses")
            require(not group.get("outstanding_assumptions"), "completed target has outstanding assumptions")
        else:
            require(group["remaining_construction_work"] or group.get("clause_limitations"), "unfinished target has no remaining task or justified clause limitations")
        clause_count+=len(group["clause_progress"])
    examples=json.loads(Path("artifacts/extraction/networks/examples.json").read_text())
    cases=json.loads(source_path("case_coverage").read_text())
    if cases["cases"] and "coverage_id" in cases["cases"][0]:
        return current_cases_review(cases, examples, groups, clause_count)
    counts={i:1 for i in range(1,28)};counts.update({11:4,15:2,16:2,17:3,19:2,20:3,21:6,22:8,23:5,25:2,26:2,27:3})
    expected={f"NET-{n:03d}-C{v:02d}" for n,count in counts.items() for v in range(1,count+1)}
    require(len(expected)==57 and {c["case_id"] for c in cases["cases"]}==expected and len(cases["cases"])==57,"57-case expansion incomplete")
    require({c["example_id"] for c in cases["cases"]}=={e["example_id"] for e in examples},"source example coverage incomplete")
    catalog=register["evidence_catalog"]
    association={}
    for key,entry in catalog.items():
        config=None;source_cases=set(entry.get("source_case_ids",[]))
        if entry.get("bundle"):
            root=Path(entry["bundle"]);mp=root/"manifest.json"
            if mp.exists():
                manifest=json.loads(mp.read_text());config=manifest.get("configuration_id");source_cases.update(manifest.get("source_case_ids",[]))
            ep=root/"events.json"
            if ep.exists():
                events=json.loads(ep.read_text());config=events.get("configuration_id",config);source_cases.update(events.get("source_case_ids",events.get("case_ids",[])))
        association[key]=(config,source_cases)
    reviewed=[]
    for case in cases["cases"]:
        require(case["status"] in {"tested_partial","rejected_unavailable"} and case["representative_status"] in {"covered","partial","unavailable"},"case still pending")
        if case["representative_status"]!="covered":require(case.get("unrepresented_reason"),"partial case has no reason")
        evidence_keys=[key for key,(config,ids) in association.items() if case["case_id"] in ids or config is not None and config in case["configuration_ids"]]
        theorems=sorted({claim["theorem"] for gid in case["requirement_group_ids"] for claim in groups[gid]["claim_dependencies"] if set(claim["evidence_keys"])&set(evidence_keys)})
        reviewed.append({"case_id":case["case_id"],"example_id":case["example_id"],"alternative":case["alternative"],"evidence_agent_representative_status":case["representative_status"],"evidence_agent_realization":case.get("representative_realization"),"remaining_aspects":case.get("unrepresented_reason"),"current_evidence_keys":evidence_keys,"related_checked_group_contributions":theorems,"construction_disposition":"unavailable_evidence" if case["status"]=="rejected_unavailable" else ("scoped_contributions_with_full_case_compliance_unproved" if theorems else "finite_evidence_or_declared_case_mapping_without_full_case_theorem"),"whole_case_compliance_established":all(groups[gid]["established"] and any(case["case_id"] in application.get("case_ids", []) for application in groups[gid].get("checked_applications", [])) for gid in case["requirement_group_ids"])})
    requests=json.loads(output_path("evidence_requests.json").read_text())["requests"]
    pending=[r["request_id"] for r in requests if r.get("pending_evidence_items")]
    report={"schema_version":"csfc-construction-coverage-review/v1","source_groups_sha256":hashlib.sha256(Path("artifacts/extraction/requirements/groups.json").read_bytes()).hexdigest(),"case_ledger_sha256":hashlib.sha256(source_path("case_coverage").read_bytes()).hexdigest(),"groups":76,"source_clauses_preserved":clause_count,"encoded_encompassing_propositions":[g["group_id"] for g in groups.values() if g["formal_definition"]],"group_statuses":dict(collections.Counter(g["status"] for g in groups.values())),"scope_counts":{g["group_id"]:len(g["established_scopes"]) for g in groups.values() if g["established_scopes"]},"representative_statuses":dict(collections.Counter(c["representative_status"] for c in cases["cases"])),"cases":reviewed,"pending_evidence_request_ids":pending,"semantic_review_limit":"Exact text/coverage checks preserve obligations. Per-group semantic establishment requires the explicit scoped Lean definitions and correspondence assumptions; source-unit counts do not prove semantic coverage."}
    output_path("coverage-review.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in {"cases","semantic_review_limit"}}))

if __name__=="__main__":review()
