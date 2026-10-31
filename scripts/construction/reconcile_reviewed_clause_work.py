"""Reopen reviewed source clauses with concrete local work and exact external limits."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

RUN = Path(os.environ["TDN_OUTPUT_DIR"])
WORK = {
    "RG-011": [
        ("single geographic site|one group", "Bind component-to-central administrator/keying assignments from central-gray-management-v3 and utility-v4. Human appointments remain unprovided organizational records.", "scripts/construction/import_management.py"),
        ("two CAs|enterprise CAs|EAP-TLS", "Bind selected certificate/PSK methods to actual CA trust identities and central AS location. Use C-AUTH-001 and final EAP v18 roles; enterprise CA use is a recommendation when available.", "scripts/construction/import_authentication.py"),
        ("Annex", "Decompose EG Annex 1.2.0 general and central-management clauses into technical predicates; replace enterpriseGrayAnnexSatisfied before any whole-scope claim. EG-FW-1..6/8..15, AR-1/4/5/25 and FW-16..29 have retained source text. Applicability and alternatives must be checked individually.", "TDN/Targets/Management.lean"),
        ("encryption|encrypted", "Instantiate the shared packet/management semantics for central Gray and Red paths. Prove Gray encryption before Outer and Red management encryption before Inner/Outer; ordinary probes alone do not discharge every execution.", "data/snapshots/2026-10-24T014455Z/central-gray-management-v3"),
        ("scale", "Treat the numerous-sites sentence as capability context. The selected configuration inventory and universal peer coverage must not be fixed to two sites.", "TDN/Targets/Management.lean"),
    ],
    "RG-039": [
        ("MSC-PF-8", "Import actual INPUT/OUTPUT management initiators and logging/authentication exceptions. For a management-free selected scope, prove no applicable management acceptance from complete hooks.", "scripts/construction/import_execution.py"),
        ("MSC-PF-13", "Prove required IKE/ESP or MKA/MACsec peer traffic is accepted using independently defined intended peers and first-match rule proofs.", "TDN/Targets/NetworkPolicies.lean"),
        ("MSC-PF-15", "Bind Gray CDP/OCSP endpoints and only their HTTP exchanges from http-crl-v1/http-ocsp-v1; retain the branch where the service is absent.", "data/snapshots/2026-10-24T014455Z/http-crl-v1"),
        ("MSC-PF-17", "Extend checked full-level peer addressing from Outer FORWARD to the complete Gray interface decision inventory under INT-014's explicit exception interpretation.", "scripts/construction/import_gray_addressing.py"),
        ("MSC-PF-18", "Derive reachable source ranges from actual ingress attachments/routes and check every accepted rule's source range is included.", "TDN/Targets/NetworkPolicies.lean"),
        ("MSC-PF-19", "Bind each enabled management/control exception to a protocol and independently supplied policy authorization. Do not equate an existing allow rule with authorization.", "TDN/Targets/NetworkPolicies.lean"),
        ("MSC-PF-20", "Check complete ordered INPUT/FORWARD/OUTPUT Gray decisions and defaults, then apply outer_gray_policy_from_local_rules.", "scripts/construction/raw_correspondence.py"),
    ],
    "RG-040": [
        ("MSC-PF-23", "Apply intended same-level peer availability to actual Gray Firewall interfaces using complete OVS/bridge/routed rule semantics.", "TDN/Targets/NetworkPolicies.lean"),
        ("MSC-PF-25", "Bind only necessary revocation HTTP tuples from retained CRL/OCSP cases and prove other HTTP rejection.", "data/snapshots/2026-10-24T014455Z/http-ocsp-v1"),
        ("MSC-PF-27", "Bind management acceptance to actual Gray Management physical-port inventory; distinguish virtual observed attachments from unprovided physical NIC facts.", "data/snapshots/2026-10-24T014455Z/central-gray-management-v3"),
        ("MSC-PF-28", "Bind every data allow rule to intended full-level Inner external endpoints, preserving explicit management/revocation/control exceptions under INT-014.", "scripts/construction/import_gray_addressing.py"),
        ("MSC-PF-29", "Check ingress-specific source reachability against raw route/attachment facts for each Gray Firewall interface.", "TDN/Targets/NetworkPolicies.lean"),
        ("MSC-PF-30", "Define required selected control services independently and prove their first-match acceptance.", "TDN/Targets/NetworkPolicies.lean"),
        ("MSC-PF-31", "Import complete Gray Firewall ordered rules and defaults, including OVS/bridge filtering, then apply gray_firewall_policy_from_local_rules.", "scripts/construction/native_runtime.py"),
        ("MSC-PF-32", "Lift full-level endpoint rejection through all Gray Firewall processing paths; retain actual shared-level namespace and address bindings.", "TDN/Targets/NetworkPolicies.lean"),
    ],
    "RG-046": [
        ("MSC-DM-7", "Bind each component's actual administration source addresses and feasible minimum range to the independently required AW inventory. Use endpoint_range_is_minimal for exact endpoint bounds.", "TDN/Targets/Management.lean"),
        ("MSC-DM-8", "Separate local administration from remote NSA-approved solution selection. Actual local/remote attachment is importable; external solution approval remains unprovided.", "data/snapshots/2026-10-24T014455Z/utility-v4/central-management"),
        ("two layers|two layers|CNSA|same LAN|requirement is not applicable", "Apply INT-046: same-LAN/VLAN exception concerns the remote two-layer approved-solution requirement; direct physical management is the explicit plaintext exception. Bind actual path/site and selected transport.", "TDN/Targets/Management.lean"),
        ("encrypted|SSHv2|Secure Shell|Transport Layer", "Import actual TLS/SSH/IPsec/MACsec service and path configuration; prove protection for selected remote transmissions and retain direct physical applicability.", "scripts/construction/import_management.py"),
        ("", "Link the management-plane definition and decimal/abbreviation fragments to their full source unit; do not count them as independent proof obligations.", "scripts/construction/reconcile_source_passages.py"),
    ],
    "RG-048": [
        ("MSC-DM-11|Owner must identify", "Keep actual individual Security Administrator appointment as an external organizational record; credential labels alone do not establish it.", "TDN/Targets/Provisioning.lean"),
        ("MSC-DM-12|generat|CSR|signed|certificate chain|unique", "Import public key/CSR/certificate fingerprints and ordered generation/request/sign/install events from retained certificate lifecycle and EAP collectors; apply installed_certificate_has_key_generation.", "TDN/Targets/Provisioning.lean"),
        ("MSC-DM-14", "Bind the certificate-request workstation's actual Gray attachment for each Outer CA interaction; ordinary data-path host roles are insufficient.", "TDN/Targets/Provisioning.lean"),
        ("out-of-band|physically secured|first use|configur", "Bind observed pre-use provisioning order and out-of-band channel. Physical secured-area authorization and complete configured-per-CP coverage remain separate requirements.", "TDN/Targets/Provisioning.lean"),
        ("initial CRL", "Record optional initial CRL applicability without inventing a mandatory initial installation.", "TDN/Targets/Provisioning.lean"),
        ("", "Join split X.509 and example fragments to their parent source unit; apply INT-048's certificate-based MACsec role reading.", "scripts/construction/reconcile_source_passages.py"),
    ],
    "RG-075": [
        ("screening router|Customer Edge Router|Black Network", "Import both existing-router and added-screening cases. Existing routers have actual routing state; the added case currently uses a filtering bridge and must retain that mechanism distinction. Prove the applicable Black boundary placement without claiming full MSC compliance.", "data/snapshots/2026-10-24T014455Z/utility-v4"),
        ("Annex|mandatory|additional controls|Additional components", "Apply INT-075: optional extra controls create no additional CP configuration/security duties. Assign independently selected annex requirements to their actual key-management scope rather than an opaque string list.", "TDN/Targets/Components.lean"),
        ("", "Link extraction fragments to the optional-control source unit.", "scripts/construction/reconcile_source_passages.py"),
    ],
}


def main():
    import re
    path = RUN / "theorem_register.json"
    previous = path.read_bytes()
    (RUN / "register-revisions" / (hashlib.sha256(previous).hexdigest() + ".json")).write_bytes(previous)
    register = json.loads(previous)
    queue = []
    for group in register["groups"]:
        name = group["group_id"]
        if name not in WORK:
            continue
        group["status"] = "construction_in_progress"
        group["established"] = False
        group["outstanding_assumptions"] = []
        group["disposition_reason"] = "Source context and available annexes support a documented reading. Concrete clause applications remain active; the inherited unresolved-interpretation status is superseded."
        tasks = []
        for clause in group["clause_progress"]:
            if clause["status"] == "context_only":
                continue
            task = next((row for row in WORK[name] if re.search(row[0], clause["text"], re.I)), None)
            if task is None:
                task = ("", "Review this narrative source unit against the explicit selected configuration and bind its independent obligations.", "TDN/Targets/Management.lean")
            clause["status"] = "construction_in_progress"
            clause["reason"] = "The source reading is available. The following concrete task remains."
            clause["formalization_work_remaining"] = task[1]
            clause["next_artifact"] = task[2]
            tasks.append(task[1])
            queue.append({"group": name, "source_id": clause["source_id"], "task": task[1], "next_artifact": task[2]})
        group["remaining_construction_work"] = list(dict.fromkeys(tasks))
        group["unfulfilled_requirement_or_construction_obligations"] = group["remaining_construction_work"]
        group["canonical_review_at"] = datetime.now(timezone.utc).isoformat()
        group["interpretation_decisions"] = {
            "RG-011": ["INT-046", "INT-011-annex"], "RG-039": ["INT-014"],
            "RG-040": ["INT-014"], "RG-046": ["INT-046"], "RG-048": ["INT-048"],
            "RG-075": ["INT-075"]}[name]
    register["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n")
    (RUN / "reviewed-clause-work-COORD041.json").write_text(json.dumps({
        "at": register["updated_at"], "groups": list(WORK), "tasks": queue,
        "source": "Original current-run layout text pages 12/15/22/24/26/29/30/45-49; retained official EG Annex 1.2.0.",
        "completion": False}, indent=2) + "\n")
    print(json.dumps({"reviewed_groups": len(WORK), "source_passage_tasks": len(queue)}))


if __name__ == "__main__":
    main()
