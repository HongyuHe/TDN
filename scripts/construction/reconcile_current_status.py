"""Replace superseded canonical dispositions while preserving the exact previous register."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

RUN = Path(os.environ["TDN_OUTPUT_DIR"])
UPDATES = {
    "RG-004": ("partial_results", "The selected ND case has actual FreeBSD/Botan Inners and Linux/OpenSSL Outers. The earlier shared-Linux case remains a counterexample, not the current universal disposition.",
               ["Manufacturer/subsidiary independence and any NSA-approved same-manufacturer alternatives require separate authoritative records.",
                "Complete source-specific library-independence and Gray-Firewall/Inner applications; observed provider names alone do not establish manufacturer independence."]),
    "RG-005": ("scoped_specification_established", "The selected multiworker component inventory satisfies the full formal physical-separation specification using actual hardware UUIDs and all helper bindings. Earlier same-host deployments remain preserved counterexamples.",
               ["Finish cross-group source accounting for embedded Components List qualifiers under RG-003 and retain exact selected-case scope in the final assessment."]),
    "RG-007": ("partial_results", "Native shared/baseline and all eight family cases have checked universal packet-stack results, actual Inner-before-Outer events and positive delivery. Independent fragment-piece applications retain both layers under the documented implementation contract.",
               ["Complete mixed arbitrary-inbound no-bypass, delivery-label and fragment/backend connections. Seven mixed stack/order applications and eighteen useful executions are already checked.",
                "Assemble encompassing Gray/Black/plaintext views and independent key-context/configuration clauses; keep cryptographic implementation assumptions explicit."]),
    "RG-008": ("partial_results", "Native shared and baseline applications prove full-label plaintext delivery restriction and positive intended delivery. Trusted public chain bindings separately support peer-level exclusion.",
               ["Assemble the encompassing connectivity target with the complete intended connectivity plan, dedicated Inner assignments and actual authenticated-peer bindings.",
                "Complete applicable non-IPsec/family delivery-isolation applications."]),
    "RG-012": ("partial_results", "Management-free shared/baseline applications bind separate public certificate authority/material contexts and cross-level peer exclusion. Optional management is not a prerequisite for those completed scopes.",
               ["Reconcile each narrative/key-separation clause against actual certificate and CAK evidence.",
                "Apply optional selected management clauses separately."]),
    "RG-014": ("partial_results", "The documented source interpretation is selected and active. Shared/baseline Gray ranges and exact raw Outer forwarding rules prove the scoped addressing target; the old unresolved-interpretation disposition is superseded.",
               ["Complete applicable Gray/management and additional-mechanism policy scopes and final source-clause accounting; do not reopen the resolved interpretation without new evidence."]),
    "RG-028": ("partial_results", "Raw-bound EAP runtime settings prove universal local controlled-port encryption, absent-SA blocking and useful emission. INT028 distinguishes ordinary and bounded Hello timers. Delay v18 and source repair evidence are available.",
               ["Import final delay-event/RX-SA/PN evidence into the general freshness theorem and complete remaining MD timer/configuration clauses.",
                "Apply retained exact final hostap source/runtime bindings and twelve IEEE Annex G vectors. Visible KDF/agility clauses are available; source completeness and other conformance clauses remain separately qualified."]),
    "RG-029": ("partial_results", "Thirty-two family component boundary applications include actual positive traversals. Inner inbound no-bypass starts with arbitrary envelopes and empty local authentication, and forces a local decrypt of the correct layer and payload.",
               ["Apply the same boundary theorem to native and MACsec components.",
                "Complete encompassing configuration/MAC-objective and outbound context connections; preserve control-traffic applicability."]),
    "RG-030": ("partial_results", "Family Outer boundary applications force an actual local decryption for arbitrary inbound envelopes and prove scoped outbound protection. Positive traversals prevent empty-boundary completion.",
               ["Complete the global Gray-arrival already-encrypted clause from actual surrounding executions.",
                "Apply unchanged boundary results to native/MACsec components and finish optional MAC/configuration clauses."]),
    "RG-033": ("partial_results", "Actual PTB/socket observations and exact ESP alignment arithmetic establish the supplemental IPv6 discovered-limit budget, including the successful UDP payload. Six importer mutations pass.",
               ["Apply mandatory sizing to the full ordinary Gray Firewall/encryption interface inventory under INT033.",
                "Complete selected Inner MACsec/encapsulation size and applicable multi-layer path budgets."]),
    "RG-034": ("partial_results", "The source-faithful target now guards firewall placement by untrusted Black applicability, binds actual paths and proves firewall existence. Native topology applications use the reusable local-check theorem.",
               ["Reconcile source clauses and complete every selected topology/transport application; preserve trusted non-public applicability tests."]),
    "RG-036": ("construction_in_progress", "INT036 replaces an unjustified unique-least-set interpretation with inclusion-minimal exposure among feasible configurations. The general proof uses Mathlib minimality.",
               ["Complete exact interface/service inventory and justified feasible alternatives, then check necessity of each admitted permission.",
                "Validate incomparable alternatives and unused-interface cases."]),
    "RG-038": ("partial_results", "Family v9 imports exact literal nft header checks before defragmentation. The retained v8 raw-only NH44 counterexample is superseded for the repaired configuration, not erased.",
               ["Complete the remaining source multicast/IPv4 options clauses and applicable native/mechanism applications.",
                "Retain kernel/hook-order binding and distinguish wire-header checks from post-defragmentation raw hooks."]),
    "RG-043": ("partial_results", "Linux v11 proves dual-family NEW conventional DNS initiation rejection and unconditional conventional IPv6 rejection. Earlier established HTTPS replies remain represented. Both actual FreeBSD guests additionally prove enabled-egress denial after every fixed-configuration packet history. Complete v13 state, scrub, translation and skip-flag inventories discharge local conditions.",
               ["Retain the fixed-rule/address/no-administrative-state-injection implementation contract.",
                "Complete resolver/service, default-access and automatic remote-boot clauses for the selected complete component inventory."]),
    "RG-069": ("partial_results", "The recorded certificate-bound administration API has universal auditor permission restrictions. Host root, Docker, other interfaces and actual human appointments remain separately scoped.",
               ["Complete recorded review-of-action/event clauses and organizational authorization evidence; do not infer human-role separation from certificate labels."])
}


UPDATES.update({
    "RG-015": ("partial_results",
        "The mixed operational model preserves opaque Ethernet, protected VLAN fields and MACsec bodies through integrated and standalone L2TP carriers. Both useful directions are checked for all six pairings, plus the bridged non-IP case.",
        ["Finish source-specific Section 11.1 technical clauses and carrier/fragment response composition. Do not treat the opaque section predicate as a completed source obligation."]),
    "RG-024": ("construction_in_progress",
        "The specification records both supplicant and authenticator functions without adding a simultaneity requirement. Final forward/reverse EAP runtime and actual binary/source bindings are available.",
        ["Import final EAP authentication and role bindings into the source-specific general theorem; preserve the individual supported mechanism scopes."]),
    "RG-026": ("construction_in_progress",
        "Official indexed IEEE clauses and retained hostap source/vector checks now identify the MSK prefix, CAK/CKN derivation and algorithm agility value. The former blanket missing-KDF-source interpretation is superseded for those visible clauses.",
        ["Apply the twelve retained Annex G vectors and final EAP runtime bindings to independent derivation, algorithm and observed-mode clauses.",
         "Keep unseen standard clauses, exact source provenance and component approvals separately qualified."]),
    "RG-027": ("construction_in_progress",
        "PSK and MKA evidence is retained and the encompassing alternative specification is present. Accepted evidence still requires clause-specific key-selection and lifecycle applications.",
        ["Import actual PSK identifiers, lengths and selected use without exposing secret bytes; apply independent key-separation and lifecycle conditions."]),
    "RG-032": ("construction_in_progress",
        "A retained fixed-size scheduled-cover mechanism supplies a concrete TRANSEC interpretation with explicit queue, clock and jitter limits. A generic unexplained source-ambiguity outcome is no longer the current work status.",
        ["Formalize and apply the actual fixed-size and scheduling guarantees. Preserve finite-buffer, clock/link assumptions and the limits of traffic-analysis claims."]),
    "RG-047": ("construction_in_progress",
        "The corrected target binds operations to an actual active session, owned account and credential-to-token mapping. Logout and credential revocation constrain use; eight positive and rejecting examples compile.",
        ["Apply the corrected session theorem to the retained per-request certificate-authenticated service under its actual source contract.",
         "Keep AW roster completeness and real individual ownership separate from synthetic credential labels."]),
    "RG-061": ("construction_in_progress",
        "Registration and version-change specifications now bind actual solution/version identities, UTC Gregorian anniversaries and event order. Leap-day, month-end and rejection tests compile.",
        ["Finish source-clause accounting and any available configuration/date applications; retain unprovided organizational approvals and registration events as exact external requirements."]),
    "RG-062": ("construction_in_progress",
        "The retention target forbids permanent logical-data loss before its actual calendar anniversary, including when inspected later. Backup windows cover data still retained at their start. Current presence is derived from deletion history.",
        ["Import retained protected offload and power-persistence transactions into independent continuity/copy-coverage results.",
         "Keep year-long retention, quarterly verification and complete retained-copy inventory requirements explicit."])
})


def main():
    path = RUN / "theorem_register.json"
    previous = path.read_bytes()
    previous_hash = hashlib.sha256(previous).hexdigest()
    revisions = RUN / "register-revisions"
    revisions.mkdir(exist_ok=True)
    (revisions / (previous_hash + ".json")).write_bytes(previous)
    register = json.loads(previous)
    now = datetime.now(timezone.utc).isoformat()
    changes = []
    for group in register["groups"]:
        key = group["group_id"]
        if key not in UPDATES:
            continue
        if group.get("established") and group.get("completion_certificate"):
            continue
        status, reason, remaining = UPDATES[key]
        changes.append({"group": key, "previous_status": group["status"], "current_status": status})
        group["status"] = status
        group["established"] = False
        group["disposition_reason"] = reason
        group["remaining_construction_work"] = remaining
        group["outstanding_assumptions"] = []
        group["unfulfilled_requirement_or_construction_obligations"] = remaining
        group["canonical_review_at"] = now
        group["canonical_review_basis"] = "Current declaration map, successful recorded attempts, immutable handoffs and explicit selected scopes."
        current = group["current_development"]
        group["lean_theorems"] = [r["name"] for r in current["general_and_supporting_results"]]
        group["checked_applications"] = current["checked_applications"]
        group["established_scopes"] = [{"conclusion": row["scope"], "theorem": row["name"],
                                       "whole_group_claim": row["whole_group_claim"]}
                                      for row in current["checked_applications"]]
        for clause in group["clause_progress"]:
            if clause.get("status") == "context_only":
                continue
            clause["status"] = "partial_result"
            clause["reason"] = reason
            clause["formalization_work_remaining"] = " ".join(remaining)
            clause["current_scoped_applications"] = [r["name"] for r in current["checked_applications"]]
            clause["claim_note"] = "Mapped group contributions do not automatically discharge this entire source passage."
            if key == "RG-004" and "MSC-PS-7" in clause["text"]:
                clause["status"] = "established"
                clause["reason"] = "The OS-family clause is established for the explicitly selected four ND encryption components. Earlier Linux-only cases remain counterexamples."
                clause["formalization_work_remaining"] = ""
            if key == "RG-005" and "selected from the CSfC Components List" not in clause["text"]:
                clause["status"] = "established"
                clause["reason"] = "The physical-separation obligation is proved for the complete selected multiworker security-component inventory. Embedded product-selection qualifications are accounted under RG-003."
                clause["formalization_work_remaining"] = ""
        if key == "RG-005":
            group["general_theorem"] = "TDN.Targets.physical_separation_from_disjoint_role_hardware"
            group["target_specification_established_in_scope"] = True
            group["scope_dependency_note"] = "Physical separation is proved. Components List eligibility is a separate RG-003 obligation; no full solution approval is claimed."
    register["updated_at"] = now
    path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n")
    record = {"at": now, "previous_register_sha256": previous_hash,
              "current_register_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
              "changes": changes, "whole_document_completion": False}
    (RUN / "canonical-status-reconciliation.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"updated_groups": len(changes), "previous_register_sha256": previous_hash}))


if __name__ == "__main__":
    main()
