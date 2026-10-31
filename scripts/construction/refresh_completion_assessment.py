"""Produce a current, explicitly incomplete all-group and source-passage assessment."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def preserve(path):
    if path.exists():
        data = path.read_bytes()
        directory = RUN / "assessment-revisions"
        directory.mkdir(exist_ok=True)
        (directory / (hashlib.sha256(data).hexdigest() + "-" + path.name)).write_bytes(data)


def declaration(item):
    location = item.get("location") or next(iter(item.get("locations", [])), {})
    target = "../../../../" + location.get("path", "")
    return "[" + item["name"] + "](" + target + ")"


def scope_accounting(group):
    selected = bool(group.get("established"))
    certificate = group.get("completion_certificate", {})
    other = group.get("other_case_application_work", [])
    work = list(dict.fromkeys(group.get("remaining_construction_work", []) + other))
    return {"selected_configuration_established": selected,
            "selected_scope": certificate.get("scope"),
            "selected_certificate": certificate or None,
            "additional_scoped_certificates": group.get("scoped_specification_certificates", []),
            "all_representative_cases_established": False,
            "other_case_application_work": other, "all_remaining_work": work}


def main():
    register_path = RUN / "theorem_register.json"
    register = json.loads(register_path.read_text())
    current = {row["group_id"]: row for row in json.loads((RUN / "current_declaration_map.json").read_text())}
    assert len(register["groups"]) == len(current) == 76
    responses = []
    for path in sorted((RUN / "responses").glob("*.json")):
        data = json.loads(path.read_text())
        responses.append((path, data))
    at = datetime.now(timezone.utc).isoformat()
    evidence_path = Path("data/snapshots/2026-10-24T014455Z/assessment-and-replay-v7") / RUN / "evidence/assessment-all76-v3.json"
    evidence = {g["group_id"]: g for g in json.loads(evidence_path.read_text())["groups"]}
    preserve(RUN / "completion_assessment.md")
    preserve(RUN / "completion_assessment.json")
    preserve(register_path)
    lines = [
        "# Construction completion assessment", "",
        "Updated " + at + ". The run remains incomplete because actionable proof, importer and source-clause work remains. This document is a current work assessment, not a stopping justification.",
        "",
        "All 76 encompassing specifications are present in the current source. The 749 indexed source passages include narrative context, recommendations and extraction fragments. They are accounting entries, not 749 independent requirements. Each group below separates the present specification, mapped general proofs, checked applications and remaining work.",
        "",
        "A checked application means that a general theorem has been applied to concrete captured facts. A model execution is a sequence allowed by the formal processing rules. A positive execution is an explicit allowed sequence that reaches delivery. The source and implementation contracts identify how those rules represent Linux, FreeBSD and cryptographic behavior.",
        "",
        "Declared implementation and collector contracts do not automatically make a proved clause unfinished. Unchecked conditions that are themselves source requirements remain gaps. Product approvals, authority decisions and organizational records remain separate from observed configuration facts. Retrieved annexes still require their technically checkable clauses to be decomposed and applied; an opaque annex-satisfied proposition does not discharge them.",
        "",
        "Current packet work includes native IPv4/ESP, eight IPv4/IPv6 ESP combinations, exact early IPv6 header gates, distributed fragmentation, arbitrary inbound tunnel checks and mixed IPsec/MACsec/L2TP local-to-global proofs. The six repaired mixed configurations discharge their stack conditions. Eighteen checked positive mixed executions cover both directions and the separate bridged opaque-Ethernet case with zero, one and two protected VLAN tags. Seven applications prove actual Inner-before-Outer encryption events. Native per-byte applications now include copied prefixes, every component response case and actual Inner-before-Outer event ancestry. Mixed inbound no-bypass has separate local checks and positive paths. Authenticated encrypted reassembly, mixed per-byte composition and remaining backend connections remain active.",
        "",
        "FreeBSD DNS v13 discharges loaded skip flags, complete rule/scrub/translation inventories and empty state preservation under a fixed configuration. Both guest applications compile and all 14 importer tests pass. Conventional DNS transport denial does not by itself discharge the remaining resolver/service and automatic-startup clauses.",
        "",
        "Evidence-side all-group accounting comes from the immutable assessment-and-replay-v7 bundle. Later accepted response files are listed per group. Those observations are inputs to construction; their availability is not a formal completion claim.",
        "",
        "Final convergence still requires current source-to-clause reconciliation, all accepted evidence applications, importer mutation tests, an integrated build, an axiom audit and representative-path validation. No remaining construction item in this document is accepted as intractable merely because it is unfinished.",
        ""
    ]
    result = {"at": at, "complete": False, "specifications_present": 76, "source_passages": 749,
              "evidence_assessment": str(evidence_path), "groups": [], "actionable_work": []}
    for group in register["groups"]:
        gid = group["group_id"]
        dev = current[gid]
        assert dev["specification"].get("location"), gid
        remaining = []
        for task in group.get("remaining_construction_work", []):
            if task.startswith("Construct or complete the encompassing proposition"):
                task = task.replace("Construct or complete the encompassing proposition",
                                    "Review and apply the present encompassing proposition", 1)
            remaining.append(task)
        group["remaining_construction_work"] = remaining
        scopes = scope_accounting(group)
        remaining_all = scopes["all_remaining_work"]
        result["actionable_work"].extend({"group": gid, "task": task} for task in remaining_all)
        group["assessment_review_at"] = at
        group["assessment_scope"] = "Current specification exists; mapped contributions are scoped. Whole-source reconciliation remains active."
        applicable_responses = [(p, r) for p, r in responses if gid in r.get("groups", [])]
        lines += ["## " + gid + ": " + group["title"], "",
                  "The encompassing specification is " + declaration(dev["specification"]) + ".",
                  "",
                  "Current registered outcome: " + str(group["status"]) + ". Complete selected-configuration specification: " +
                  ("established" if group.get("established") else "not claimed") +
                  ". Completion across all representative cases: not claimed.",
                  ""]
        if group.get("target_specification_established_in_scope"):
            lines += ["The selected scope establishes the target specification. Cross-accounted clauses and wider solution claims remain separately identified in the register.", ""]
        if scopes["selected_scope"]:
            lines += ["Exact selected scope: " + scopes["selected_scope"], ""]
        for scoped in scopes["additional_scoped_certificates"]:
            lines += ["Additional checked specification scope: " + scoped["scope"], ""]
        general = dev["general_and_supporting_results"]
        apps = dev["checked_applications"]
        lines += ["Mapped general and supporting proofs: " +
                  ("; ".join(declaration(x) for x in general) if general else
                   "mapping or proof construction remains active; no absence of the specification is inferred") + ".", ""]
        if apps:
            lines += ["Checked applications:", ""]
            lines += ["- " + declaration(x) + ": " + x["scope"] + "." for x in apps]
            lines.append("")
        else:
            lines += ["No checked concrete application is currently mapped for the whole selected obligation. Available evidence and independent clause proofs still require reconciliation.", ""]
        lines += ["Remaining work across the selected scope and other representative cases:", ""]
        lines += ["- " + task for task in remaining_all] if remaining_all else [
            "- No task is listed in the current group fields. Representative-case coverage still needs explicit reconciliation before any all-case completion claim."]
        lines.append("")
        if scopes["other_case_application_work"]:
            lines += ["The other-case tasks above remain actionable even when the selected specification is proved.", ""]
        if applicable_responses:
            lines += ["Current response inputs: " + ", ".join("[" + r.get("id", p.stem) +
                      "](responses/" + p.name + ")" for p, r in applicable_responses) + ".", ""]
        evidence_group = evidence[gid]
        lines += ["Evidence-side disposition in the immutable v7 assessment: " +
                  str(evidence_group.get("evidence_disposition", "see linked assessment")) +
                  ". Later response inputs may supersede that disposition; they remain construction tasks until imported and checked.", "",
                  "Source-passage accounting:", ""]
        old_clauses = {x["source_id"]: x for x in group.get("clause_progress", [])}
        passages = []
        links = {row["source_id"]: row for row in group.get("source_passage_links", [])}
        for passage in group["source_passages"]:
            sid = passage["source_id"]
            clause = old_clauses.get(sid, {})
            status = clause.get("status", "accounted-review-pending")
            reason = clause.get("reason", "Formal force and clause mapping remain under review in the group context.")
            passages.append({"source_id": sid, "registered_status": status, "reason": reason,
                             "text": passage["text"], "locations": passage.get("locations", []),
                             "counted_as_independent_requirement": False,
                             "source_unit_link": links.get(sid, {})})
            text = passage["text"].replace("\n", " ")
            lines += ["- " + sid + " — " + text, "  Current passage record: " + status + ". " + reason]
        lines.append("")
        result["groups"].append({"group_id": gid, "specification": dev["specification"],
                                 "mapped_general_results": general, "checked_applications": apps,
                                 **scopes,
                                 "registered_status": group["status"], "remaining_work": remaining_all,
                                 "source_passages": passages, "source_clause_records": group.get("source_clause_records", []),
                                 "limitation_accepted_as_stopping_reason": False,
                                 "responses": [str(p) for p, _ in applicable_responses]})
    result["stronger_stopping_assessment"] = {
        "may_stop": False,
        "reason": "Selected configuration proofs do not discharge uncompleted representative-case, source-clause or accepted-evidence applications.",
        "listed_actionable_tasks": len(result["actionable_work"]),
        "other_case_tasks": sum(len(g["other_case_application_work"]) for g in result["groups"])}
    practical_path = RUN / "practical-provability.json"
    if practical_path.exists():
        practical = json.loads(practical_path.read_text())
        result["revised_stopping_condition"] = practical["stopping_condition"]
        result["practical_coverage"] = practical["counts"]
        result["all_76_fully_established"] = False
        result["stopping_assessment"] = {
            "coverage_threshold_satisfied": practical["may_stop_under_revised_condition"],
            "final_validation_and_coordinator_review_required": True,
            "basis": "practical-provability.json",
            "stronger_work_remains": True}
        positive = practical["counts"].get("meaningful_positive_partial", 0)
        unsupported = practical["counts"].get("no_positive_clause_supported_currently", 0)
        summary = [
            "# Construction assessment under the revised stopping condition", "",
            f"The user revised the stopping condition to require one meaningful positive partial proof for every practically eligible group. The current source-reviewed classification contains {positive} eligible groups and {unsupported} groups without a supported positive clause in the available setup. Every eligible group now has a named reusable proof and checked concrete application.", "",
            f"The {positive} groups represent {positive/76:.1%} of all 76 groups. The other {unsupported} represent {unsupported/76:.1%}; their reasons concern current source and evidence support, not mathematical impossibility. Several results support overlapping clauses in more than one group. The report does not claim {positive} independent complete specifications.", "",
            "See [practical-provability.md](practical-provability.md) for all 76 classifications, exact clause scopes, proof names and evidence paths. Final combined validation and coordinator review determine publication. Whole-document compliance remains unproved.", "",
            "The original stronger assessment follows. Its unfinished work is retained for future work and is no longer a prerequisite for the revised stopping condition. Historical statements about exhaustive convergence below apply only to that stronger objective.", "",
            "## Preserved stronger full-clause assessment", ""]
        lines = summary + lines
    else:
        result["stopping_assessment"] = result["stronger_stopping_assessment"]
    register_path.write_text(json.dumps(register, indent=2) + "\n")
    (RUN / "completion_assessment.md").write_text("\n".join(lines) + "\n")
    (RUN / "completion_assessment.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"groups": len(result["groups"]), "source_passages": sum(len(g["source_passages"])
                     for g in result["groups"]), "complete": False}))


if __name__ == "__main__":
    main()
