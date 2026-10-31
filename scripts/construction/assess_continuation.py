"""Preserve all source clauses and generate a candid live continuation assessment."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    run = Path(args.run)
    path = run / "theorem_register.json"
    register = json.loads(path.read_text())
    declarations = {}
    for source in Path("TDN/Targets").glob("*.lean"):
        for match in re.finditer(r"^(def|theorem|lemma|tdn_data)\s+([A-Za-z0-9_]+)", source.read_text(), re.M):
            declarations[match[2]] = {"kind": match[1], "module": str(source), "name": "TDN.Targets." + match[2]}
    for group in register["groups"]:
        name = group["top_level_target"]
        if name in declarations:
            group["formal_definition"] = declarations[name]["name"]
            group["continuation_definition_source"] = declarations[name]["module"]
            if group["group_id"] != "RG-012":
                group["continuation_review"]["state"] = "specification_present_requires_clause_audit"
    register["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(register, indent=2) + "\n")
    lines = ["# Completion assessment", "", "The run is incomplete and remains active. No claim is made that all practically tractable proofs are finished. Existing inherited status labels are starting information, not accepted limitations. New checked results are listed separately from old contributions.", "", "## New checked construction", "", "- CSLib pinned compatibility experiment and active labelled pipeline compiled. Local outbound-policy atoms select actual installed matching associations; payload identity is preserved. Global packet protection and delivery exclusion remain under construction.", "- RG-012 authority/key separation and authentication exclusion use a general proof. Fresh baseline and four-level shared configurations instantiate it with verified public-key fingerprints and complete loaded/configured self-signed roots. Optional management is explicitly unselected for those scopes.", "- Generic guarded event histories derive prior-event witnesses. RG-067 applies that proof to revocation/destruction initiation before disposal. Organizational event applications remain absent.", "- INT-061 keeps both version deadlines. A checked minimum-deadline theorem proves both upper bounds. Actual organizational dates remain absent.", "- Components specifications include OS-family and physical-device separation; general counterexample theorems make actual violations provable. A distinct-physical-worker alternative is requested in C-SEPARATION-001.", "", "## Per-group and per-clause accounting", ""]
    for group in register["groups"]:
        lines.extend(["### " + group["group_id"] + ": " + group["title"], "", "Specification: " + (group["formal_definition"] or "not yet constructed") + ". General theorem: " + group.get("general_theorem", "not yet recorded") + ".", "", "Current scoped result: " + ("FreshBaselineTrust.snapshot_RG012_management_free and FreshSharedTrust.snapshot_RG012_management_free compiled; fingerprint/chain import details in trust-partition-import.json. Scope excludes optional management. Source-to-model and finite-interval assumptions remain explicit." if group["group_id"] == "RG-012" else "Inherited contributions require fresh reconciliation; any new definition still requires clause-by-clause source and application review."), "", "Remaining work:", ""])
        for task in group["remaining_construction_work"]:
            lines.append("- " + task)
        lines.extend(["", "No unsupported stopping reason is accepted. Missing code or a failed proof is actionable. External evidence limitations must be supported by a current response, official-source retrieval, or tested capability assessment.", "", "| Source clause | Current construction accounting |", "|---|---|"])
        for clause in group["clause_progress"]:
            text = clause["text"].replace("|", "\\|").replace("\n", " ")
            lines.append("| " + clause["source_id"] + " " + text + " | Pending fresh clause-to-definition/theorem/application reconciliation. Inherited status: " + clause["status"] + ". |")
        lines.append("")
    (run / "completion_assessment.md").write_text("\n".join(lines))
    print(json.dumps({"groups": len(register["groups"]), "clauses": sum(len(g["clause_progress"]) for g in register["groups"]), "specifications": sum(bool(g["formal_definition"]) for g in register["groups"]), "complete": False}))


if __name__ == "__main__":
    main()
