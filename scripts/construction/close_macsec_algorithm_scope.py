"""Record the complete selected MACsec algorithm scope and its explicit runtime contract."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from close_verified_configuration_scopes import certificate

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def main():
    path = RUN / "theorem_register.json"
    prior = path.read_bytes()
    revision = RUN / "register-revisions"
    revision.mkdir(exist_ok=True)
    (revision / (hashlib.sha256(prior).hexdigest() + ".json")).write_bytes(prior)
    register = json.loads(prior)
    report_path = RUN / "final-macsec-algorithms.json"
    report = json.loads(report_path.read_text())
    key = "current:final-eap-v18-macsec-algorithms"
    register["evidence_catalog"][key] = {
        "kind": "reviewed_source_and_observed_runtime_algorithms",
        "report": str(report_path), "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "runtime_cases": [{"path": row["path"], "manifest_sha256": row["manifest_sha256"],
                          "observations": row["observations"]} for row in report["cases"]],
        "source_bindings": report["source_bindings"], "finite_vectors": report["finite_vectors"]}
    group = next(row for row in register["groups"] if row["group_id"] == "RG-025")
    proof = "TDN.Imported.FinalMACsecAlgorithms.selected_runtime_algorithms"
    cert = certificate(
        "Every MACsec data port in the final v18 forward and reverse EAP arrangements, four port instances across two cases.",
        [key], group["formal_definition"] + " TDN.Imported.FinalMACsecAlgorithms.devices",
        proof, report["implementation_contract"],
        ["Other MACsec deployments and later reconfiguration require their own source/runtime bindings.",
         "The result is the complete MD1/MD2 algorithm requirement for this scope. Full EAP/IEEE conformance, authority approval and key lifecycle are separately accounted."])
    cert["covered_source_ids"] = []
    for clause in group["clause_progress"]:
        clause["status"] = "established"
        clause["reason"] = ("MD1: reviewed final EAP wrappers derive CAK32; KAY derives KEK32 and invokes AES wrap with that length. "
                            "MD2: complete raw-bound software MACsec interface inventory uses GCM-AES-256. "
                            "Compilation, primitive semantics and recorded build-output identity continuity are explicit implementation contracts.")
        clause["formalization_work_remaining"] = ""
        clause["current_scoped_applications"] = [proof]
        cert["covered_source_ids"].append(clause["source_id"])
    group["status"] = "established_selected_configuration"
    group["established"] = True
    group["target_specification_established_in_scope"] = True
    group["general_theorem"] = "TDN.Targets.macsec_algorithms_from_local_checks"
    group["completion_certificate"] = cert
    group["remaining_construction_work"] = []
    group["outstanding_assumptions"] = []
    group["unfulfilled_requirement_or_construction_obligations"] = []
    group["disposition_reason"] = "Both independent RG025 clauses hold for the four selected final runtime port instances under the explicitly recorded source/runtime and cryptographic implementation contract."
    group["other_case_application_work"] = ["Map PSK/manual-key and other representative MACsec cases to their actual key-wrap and data-cipher implementations; no universal all-case claim follows."]
    for row in group["checked_applications"]:
        row["whole_group_claim"] = row["name"] == proof
    register["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"group": "RG-025", "selected_ports": len(report["devices"]), "closed_application": proof}))


if __name__ == "__main__":
    main()
