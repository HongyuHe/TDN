import collections
import hashlib
import json
from pathlib import Path
from source_paths import source_path,output_path
from validate_evidence import require


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
        require(group["disposition_reason"] and group["remaining_construction_work"] and all(c["status"]!="pending" for c in group["clause_progress"]),"target disposition missing")
        require(group["established"] is False,"blanket establishment over all emulations is forbidden")
        clause_count+=len(group["clause_progress"])
    examples=json.loads(Path("artifacts/extraction/networks/examples.json").read_text())
    cases=json.loads(source_path("case_coverage").read_text())
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
        reviewed.append({"case_id":case["case_id"],"example_id":case["example_id"],"alternative":case["alternative"],"evidence_agent_representative_status":case["representative_status"],"evidence_agent_realization":case.get("representative_realization"),"remaining_aspects":case.get("unrepresented_reason"),"current_evidence_keys":evidence_keys,"related_checked_group_contributions":theorems,"construction_disposition":"unavailable_evidence" if case["status"]=="rejected_unavailable" else ("scoped_contributions_with_full_case_compliance_unproved" if theorems else "finite_evidence_or_declared_case_mapping_without_full_case_theorem"),"whole_case_compliance_established":False})
    requests=json.loads(output_path("evidence_requests.json").read_text())["requests"]
    pending=[r["request_id"] for r in requests if r.get("pending_evidence_items")]
    report={"schema_version":"csfc-construction-coverage-review/v1","source_groups_sha256":hashlib.sha256(Path("artifacts/extraction/requirements/groups.json").read_bytes()).hexdigest(),"case_ledger_sha256":hashlib.sha256(source_path("case_coverage").read_bytes()).hexdigest(),"groups":76,"source_clauses_preserved":clause_count,"encoded_encompassing_propositions":[g["group_id"] for g in groups.values() if g["formal_definition"]],"group_statuses":dict(collections.Counter(g["status"] for g in groups.values())),"scope_counts":{g["group_id"]:len(g["established_scopes"]) for g in groups.values() if g["established_scopes"]},"representative_statuses":dict(collections.Counter(c["representative_status"] for c in cases["cases"])),"cases":reviewed,"pending_evidence_request_ids":pending,"semantic_review_limit":"Exact text/coverage checks preserve obligations. Per-group semantic establishment requires the explicit scoped Lean definitions and correspondence assumptions; source-unit counts do not prove semantic coverage."}
    output_path("coverage-review.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in {"cases","semantic_review_limit"}}))

if __name__=="__main__":review()
