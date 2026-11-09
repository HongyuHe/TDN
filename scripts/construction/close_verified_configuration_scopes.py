"""Record closed configuration specifications without claiming full solution compliance."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def certificate(scope, evidence_keys, goal, proof, contract, exclusions):
    return {"scope": scope, "evidence_keys": evidence_keys,
            "application": {"lean_goal": goal, "lean_proof": proof},
            "implementation_contract": contract, "scope_exclusions": exclusions,
            "requirement_premises_checked": True,
            "review_limit": "Metadata records scope and evidence. Lean checks the actual closed specification application; source fidelity and deployment correspondence require independent review."}


def main():
    path = RUN / "theorem_register.json"
    prior = path.read_bytes()
    revisions = RUN / "register-revisions"
    revisions.mkdir(exist_ok=True)
    (revisions / (hashlib.sha256(prior).hexdigest() + ".json")).write_bytes(prior)
    register = json.loads(prior)
    groups = {group["group_id"]: group for group in register["groups"]}
    for name in ["baseline", "shared"]:
        report_path = RUN / ("fresh-" + name + "-vpn-modes.json")
        report = json.loads(report_path.read_text())
        key = "current:complete-" + name + "-vpn-modes"
        register["evidence_catalog"][key] = {
            "kind": "complete_loaded_configuration", "bundle": report["bundle"],
            "manifest_sha256": report["validation"]["source_manifest_sha256"],
            "snapshot_sha256": report["validation"]["source_snapshot_sha256"],
            "report": str(report_path), "report_sha256": digest(report_path),
            "gateway_count": len(report["bindings"]),
            "observation_bindings": report["bindings"]}
    group = groups["RG-022"]
    spec = group["formal_definition"]
    contract = "Exact-file strongSwan loader, explicit proposal-token semantics, complete captured gateway/connection/CHILD inventory and RFC7296 implementation correspondence. No requirement clause is supplied as an unchecked premise."
    primary = certificate(
        "All eight VPN gateways and every loaded connection/CHILD in native baseline NB at the retained configuration load/runtime interval. Both IKE and ESP select the GCM objective alternatives.",
        ["current:complete-baseline-vpn-modes"],
        spec + " TDN.Deployments.FreshBaselineVPNModes.policies",
        "TDN.Deployments.FreshBaselineVPNModes.complete_loaded_mode_configuration",
        contract, ["Arbitrary later reconfiguration and whole-solution compliance are outside this fixed configuration claim."])
    primary["covered_source_ids"] = []
    for clause in group["clause_progress"]:
        text = clause["text"]
        if text.startswith(("MSC-VG-10 ", "MSC-VG-11 ")):
            clause["status"] = "not_applicable"
            clause["reason"] = "The complete selected gateway inventory uses the corresponding GCM objective alternative: VG18 for IKE and VG12 for ESP."
        else:
            clause["status"] = "established"
            clause["reason"] = "Every selected gateway is loaded as IKEv2 and every configured IKE/ESP proposal uses GCM; exact-file load and complete runtime inventories are bound to raw observations."
            primary["covered_source_ids"].append(clause["source_id"])
        clause["formalization_work_remaining"] = ""
        clause["current_scoped_applications"] = [
            "TDN.Deployments.FreshBaselineVPNModes.complete_loaded_mode_configuration",
            "TDN.Deployments.FreshSharedVPNModes.complete_loaded_mode_configuration"]
    group["status"] = "established_selected_configuration"
    group["established"] = True
    group["target_specification_established_in_scope"] = True
    group["general_theorem"] = "TDN.Requirements.vpn_mode_policies_from_complete_local_checks"
    group["completion_certificate"] = primary
    group["scoped_specification_certificates"] = [certificate(
        "All ten VPN gateways and every loaded connection/CHILD in the native four-level shared snapshot. Both IKE and ESP select GCM objective alternatives.",
        ["current:complete-shared-vpn-modes"],
        spec + " TDN.Deployments.FreshSharedVPNModes.policies",
        "TDN.Deployments.FreshSharedVPNModes.complete_loaded_mode_configuration",
        contract, ["Other deployments and later reconfiguration need their own complete inventory application."])]
    group["remaining_construction_work"] = []
    group["outstanding_assumptions"] = []
    group["unfulfilled_requirement_or_construction_obligations"] = []
    group["disposition_reason"] = "The complete selected baseline configuration establishes every applicable RG022 source clause through IKEv2 and the IKE/ESP GCM objectives. The same general theorem applies unchanged to all ten gateways of the selected shared configuration. No whole-solution approval follows."
    group["checked_applications"] = group["current_development"]["checked_applications"]
    for row in group["checked_applications"]:
        row["whole_group_claim"] = row["name"] == primary["application"]["lean_proof"]
    group["other_case_application_work"] = ["Reconcile additional native/backend/cipher cases with their own loaded inventories; no universal claim over all retained experiments is made."]

    physical = groups["RG-005"]
    physical_report = RUN / "fresh-physical-partition-import.json"
    data = json.loads(physical_report.read_text())
    key = "current:physical-partition"
    bundles = sorted({bundle for worker in data["workers"] for bundle in worker["bundles"]})
    register["evidence_catalog"][key] = {
        "kind": "physical_role_partition", "report": str(physical_report),
        "report_sha256": digest(physical_report),
        "bundles": [{"path": bundle, "manifest_sha256": digest(Path(bundle) / "manifest.json")} for bundle in bundles]}
    physical["scoped_specification_certificates"] = [certificate(
        "Physical separation for the complete selected multiworker security-component inventory, with Inner Firewall unselected.",
        [key], physical["formal_definition"] + " TDN.Deployments.FreshPhysicalPartition.components",
        "TDN.Deployments.FreshPhysicalPartition.captured_role_pairs_are_physically_distinct",
        data["remaining_assumptions"],
        ["Components List qualifiers in narrative passages are separately accounted under RG003 and remain unfulfilled for the custom stack.",
         "The closed physical-separation specification does not establish product approval, OS diversity, facility protection or physical NIC separation."])]
    for clause in physical["clause_progress"]:
        if "selected from the CSfC Components List" in clause["text"]:
            clause["status"] = "partial_result"
            clause["reason"] = "Physical separation is proved for the selected complete component inventory. The embedded Components List qualification remains an independent unfulfilled RG003 condition."
    physical["established"] = False
    physical["target_specification_established_in_scope"] = True
    physical["remaining_construction_work"] = ["Finish cross-group source accounting of Components List qualifiers under RG003; the full physical-separation specification itself has a closed checked application."]
    register["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"RG022": "established selected complete configuration",
                      "RG005": "closed physical specification; independent source approval qualifiers remain",
                      "closed_applications": 3}))


if __name__ == "__main__":
    main()
