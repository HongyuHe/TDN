"""Reconcile measured clock and final MACsec configuration contributions."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def main():
    path = RUN / "theorem_register.json"
    before = path.read_bytes()
    revisions = RUN / "register-revisions"
    revisions.mkdir(exist_ok=True)
    (revisions / (hashlib.sha256(before).hexdigest() + ".json")).write_bytes(before)
    register = json.loads(before)
    groups = {g["group_id"]: g for g in register["groups"]}
    for key, filename in [
        ("current:final-macsec-protection", "final-macsec-protection.json"),
        ("current:independent-clock-corrections", "fresh-clock-corrections.json")]:
        report = RUN / filename
        register["evidence_catalog"][key] = {
            "kind": "raw_bound_selected_configuration_or_event_contribution",
            "report": str(report),
            "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            "scope": "The report preserves exact source and observations, complete selected inventories, and explicit remaining requirements."}
    protection = groups["RG-028"]
    protection.update(
        status="partial_results", established=False,
        disposition_reason="The four final v18 controlled ports satisfy the complete parameter predicate under the recorded implementation contract. External physical-interface paths and other selected cases still need separate clause applications.",
        remaining_construction_work=[
            "Connect MD10 external-facing data traffic to every physical-parent transmit path, including direct lower-interface traffic. The controlled-port theorem covers its modeled transmit operation; it does not itself prohibit another path.",
            "Apply MD7/8/9/12/16 to other representative PSK/manual/XPN cases with their actual settings. The four final EAP ports are one selected configuration.",
            "Keep any claimed physical delay bound separate from enablement. Bind authenticated PN sample age, association continuity and receiver time to SequenceFreshness before asserting a universal age limit."],
        general_theorem="TDN.Targets.macsec_protection_from_local_checks")
    proof = "TDN.Imported.FinalMACsecProtection.selected_protection_configuration"
    for clause in protection["clause_progress"]:
        clause.update(
            status="partial_contribution_full_clause_unproved",
            whole_clause_established=False,
            current_scoped_applications=[proof],
            lean_theorems=[proof],
            evidence_keys=["current:final-macsec-protection"],
            formalization_work_remaining="Apply the selected configuration result to the remaining cases and bind every external physical-interface data path where MD10 applies.")
        clause["reason"] = {
            "p041:u012": "Both final EAP arrangements bind the enabled timed-PN source, both receive callbacks, active delay-protect advertisements and four effective ports. Sixteen finite controls support the enabled mechanism; they do not establish an unconditional physical age theorem.",
            "p041:u013": "Every final port reports normal Hello 2000 ms, active bounded Hello 500 ms and lifetime 6000 ms. INT-028 distinguishes the normal limit from the active bounded interval.",
            "p041:u014": "Every final port has observed replay window zero and useful traffic. Zero is the least natural-number window; the argument does not assert that other values are infeasible.",
            "p041:u015": "Every modeled controlled-port data emission is fully encrypted, and absent associations block emission. Completeness of physical-parent data paths remains a separate MD10 obligation.",
            "p042:u003": "Final software-port settings and source binding establish confidentiality offset zero for the selected four ports.",
            "p042:u007": "The exact loaded configuration uses macsec_policy=1, and the runtime controlled-port transmit contract requires protection."}.get(clause["source_id"].split(":")[-2] + ":" + clause["source_id"].split(":")[-1], "Selected parameter contribution.")
    clocks = groups["RG-042"]
    clockproof = "TDN.Imported.FreshClockCorrections.each_observed_correction_reduces_offset"
    clocks.update(
        status="partial_results", established=False,
        general_theorem="TDN.Targets.trusted_time_from_component_assignments",
        disposition_reason="Four actual independent guest corrections improve the measured offsets. Source trust, required Gray Management placement and continuing synchronization are not established.",
        remaining_construction_work=[
            "SR3: establish trust in the selected Red authority and continuing synchronization for the applicable Inner and selected Red management inventory. The retained temporary laboratory servers have been removed.",
            "SR4: establish an authority in the Gray Management Network and its trust, then cover applicable Outers, selected Gray management services and Gray Firewalls. The retained source is attached to the Gray data network.",
            "Apply the existing assignment theorem only when trust, placement and synchronization premises have concrete evidence. No new remote collection is authorized in the current continuation."])
    for clause in clocks["clause_progress"]:
        gray = clause["source_id"].endswith("u006")
        clause.update(
            status="partial_contribution_full_clause_unproved", whole_clause_established=False,
            current_scoped_applications=[clockproof], lean_theorems=[clockproof],
            evidence_keys=["current:independent-clock-corrections"],
            reason=("Two actual Linux Outer corrections leave measured offsets -16 and 3 microseconds. The source is on the Gray data interface, not an established Gray Management source." if gray else
                    "Two actual FreeBSD Inner corrections leave measured offsets 26 and 18 microseconds. Actual -b commands and subsequent queries are source- and guest-bound."),
            formalization_work_remaining=clocks["remaining_construction_work"][1 if gray else 0])
    cnsa = groups["RG-026"]
    cnsa["remaining_construction_work"] = [
        "Bind final TLS1.3, certificate and EAP negotiation facts to the encompassing EAP profile specification, including all selected peer/AS roles and referenced protocol conditions.",
        "Reconcile the retained classical threshold and final objective configurations as separate applicable cases. The final negotiated algorithm fields and twelve public KDF vectors are already checked.",
        "Keep unseen standard clauses and component approvals separate from the retrieved visible KDF/agility facts."]
    cnsa["current_algorithm_contribution"] = {
        "application": "TDN.Imported.FinalMACsecRuntime.negotiated_suite_cnsa2",
        "scope": "Final EAP negotiated algorithm fields only; the complete profile remains unproved."}
    register["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"reconciled": ["RG-026", "RG-028", "RG-042"], "whole_group_completion_claim": False}))


if __name__ == "__main__":
    main()
