"""Record current native topology applications and their declared transport applicability."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from close_verified_configuration_scopes import certificate

RUN = Path(os.environ["TDN_OUTPUT_DIR"])
ARGUMENTS = ["untrustedBlack", "publicInternet", "grayRequired", "edge", "grayConnection",
             "outer", "firewall", "black", "grayFirewall", "inner", "insideAttachment",
             "outsideAttachment", "externalConnection"]


def main():
    path = RUN / "theorem_register.json"
    prior = path.read_bytes()
    (RUN / "register-revisions" / (hashlib.sha256(prior).hexdigest() + ".json")).write_bytes(prior)
    register = json.loads(prior)
    group = next(row for row in register["groups"] if row["group_id"] == "RG-034")
    certificates = []
    for label, namespace in [("baseline", "FreshBaselineTopology"), ("shared", "FreshSharedTopology")]:
        report_path = RUN / ("fresh-" + label + "-topology.json")
        report = json.loads(report_path.read_text())
        key = "current:" + label + "-outer-firewall-topology"
        register["evidence_catalog"][key] = {
            "kind": "complete_observed_native_topology",
            "report": str(report_path), "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "manifest_sha256": report["manifest_sha256"], "snapshot_sha256": report["snapshot_sha256"],
            "scenario_declaration": report["scenario_declaration"],
            "scenario_declaration_path": report["scenario_declaration_path"],
            "scenario_declaration_sha256": report["scenario_declaration_sha256"],
            "observed_links": report["observed_links"], "device_order": report["device_order"]}
        prefix = "TDN.Imported." + namespace + "."
        goal = group["formal_definition"] + " " + " ".join(prefix + name for name in ARGUMENTS)
        certificates.append(certificate(
            "Every Outer component in the current native " + label +
            " snapshot, selected as an untrusted Public Internet emulation with required Gray Firewalls.",
            [key], goal, prefix + "snapshot_public_internet_RG034", report["assumptions"],
            ["The scenario label declares representative transport applicability; it does not claim a real Internet attachment.",
             "The topology overapproximates device-internal connectivity. Firewall packet-policy correctness is a separate source group.",
             "Other configurations and future topology changes require their own complete observed graph."]))
    primary = certificates[0]
    primary["covered_source_ids"] = []
    for clause in group["clause_progress"]:
        if clause["status"] == "context_only":
            continue
        if clause["text"].startswith("Otherwise, the external interface"):
            clause["status"] = "not_applicable"
            clause["reason"] = "The selected snapshots instantiate the Public Internet branch. The non-public branch remains represented in the encompassing specification."
        else:
            clause["status"] = "established"
            clause["reason"] = ("Complete observed attachments place every Outer outside port at an Outer Firewall inside port, "
                                "with its outside port connected to declared Black transport. A checked graph separator proves all "
                                "Outer-to-Black paths cross a firewall. Explicit Gray paths reach the selected Gray Firewalls.")
            primary["covered_source_ids"].append(clause["source_id"])
        clause["formalization_work_remaining"] = ""
        clause["current_scoped_applications"] = [cert["application"]["lean_proof"] for cert in certificates]
    group["status"] = "established_selected_configuration"
    group["established"] = True
    group["target_specification_established_in_scope"] = True
    group["general_theorem"] = "TDN.Targets.outer_firewall_placement_from_local_checks"
    group["completion_certificate"] = primary
    group["scoped_specification_certificates"] = certificates[1:]
    group["remaining_construction_work"] = []
    group["outstanding_assumptions"] = []
    group["unfulfilled_requirement_or_construction_obligations"] = []
    group["disposition_reason"] = "All applicable RG034 placement clauses are proved for the selected complete current native baseline topology, with the same general proof applied to the shared topology."
    group["other_case_application_work"] = ["Apply the unchanged topology theorem to other representative configurations after their current complete graph and scenario bindings are checked."]
    for row in group["checked_applications"]:
        row["whole_group_claim"] = row["name"] == primary["application"]["lean_proof"]
    register["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"group": "RG-034", "current_native_applications": 2}))


if __name__ == "__main__":
    main()
