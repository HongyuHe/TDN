"""Record the selected existing-router permission scope without hiding other cases."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from close_verified_configuration_scopes import certificate

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def main():
    path = RUN / "theorem_register.json"
    before = path.read_bytes()
    revisions = RUN / "register-revisions"
    revisions.mkdir(exist_ok=True)
    (revisions / (hashlib.sha256(before).hexdigest() + ".json")).write_bytes(before)
    register = json.loads(before)
    group = next(g for g in register["groups"] if g["group_id"] == "RG-075")
    report_path = RUN / "fresh-optional-screening.json"
    report = json.loads(report_path.read_text())
    key = "current:existing-Black-screening-router-placement"
    proof = "TDN.Imported.FreshOptionalScreening.selected_optional_control_placement"
    register["evidence_catalog"][key] = {
        "kind": "complete_observed_attachments_with_declared_architectural_boundary",
        "report": str(report_path), "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "bundle": report["bundle"], "manifest_sha256": report["manifest_sha256"],
        "observations": report["used_observations"], "source_hashes": report["source_hashes"]}
    cert = certificate(
        "The two existing Black screening routers in utility-v4/screen-existing. Optional key-management components are not selected.",
        [key], "TDN.Targets.msc_additional_control_permissions TDN.Imported.FreshOptionalScreening.controls",
        proof,
        ["Collected command output and namespace inventories are accurate.",
         "The reviewed source roles identify the selected architecture. Its MSC boundary contains IA, IB, OA and OB; it is an architectural declaration, not a physical measurement."],
        report["scope"])
    cert["covered_source_ids"] = []
    cert["inapplicable_source_ids"] = []
    for clause in group["clause_progress"]:
        sid = clause["source_id"]
        fragment = sid.endswith("p026:u010.s004")
        mandatory = sid.endswith("p026:u010.s006")
        clause["status"] = "established" if mandatory else "context_only"
        clause["reason"] = (
            "The complete observed attachment inventory places both actual routing/filtering components on Black. Their declared architectural membership excludes the MSC solution. The unchanged general theorem checks both conditions."
            if mandatory else
            "Permissive context and alternatives impose no mandatory addition. INT-075 preserves the optionality and the statement that this CP adds no independent configuration/security duty. The selected case uses existing routers; the added alternative remains separately accounted.")
        if fragment:
            clause["reason"] = "The extracted 'g.' fragment belongs to the reconstructed example in p026:u010; it has no independent formal force."
        clause["formalization_work_remaining"] = ""
        clause["current_scoped_applications"] = [proof] if mandatory else []
        if mandatory:
            cert["covered_source_ids"].append(sid)
    for unit in group.get("source_clause_records", []):
        unit["decomposition_complete"] = True
        unit["status"] = "selected_scope_established"
        unit["completion_claim"] = True
        unit["exact_clause_result"] = [{
            "kind": "permission_and_scope" if "p022:" in unit["source_unit_id"] else "screening_boundary_condition",
            "scope": cert["scope"],
            "result": "Optional additions remain optional; selected screening routers have Black placement outside the declared MSC component boundary.",
            "application": proof,
            "interpretation": "INT-075",
            "evidence": [key]}]
        unit["alternative_accounting"] = [
            {"case": "existing screening router", "status": "selected_scope_established"},
            {"case": "added screening component", "status": "separate_filtering_bridge_evidence_requires_case_interpretation"},
            {"case": "optional key-management components", "status": "not_selected_in_this_application; applicable annex clauses remain elsewhere"}]
    group.update(status="established_selected_configuration", established=True,
                 target_specification_established_in_scope=True, completion_certificate=cert,
                 remaining_construction_work=[], outstanding_assumptions=[],
                 unfulfilled_requirement_or_construction_obligations=[],
                 general_theorem="TDN.Targets.additional_controls_from_black_screening_placement",
                 disposition_reason="The selected existing-router optional-control scope is complete under INT-075 and the recorded architectural-boundary interpretation.",
                 other_case_application_work=[
                     "Review the added-screen filtering bridge against the router alternative. Import its placement separately without asserting an unobserved routing function.",
                     "Keep independently selected key-management annex duties in their applicable authentication/key-management groups; RG075 does not erase those duties."])
    register["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"group": "RG-075", "scope": "two existing Black screening routers", "all_case_completion": False}))


if __name__ == "__main__":
    main()
