"""Map catalog groups to the current Lean source lines."""
import argparse
import json
from pathlib import Path
import re

from requirement_clauses import render as render_clauses


ROOT = Path(__file__).resolve().parents[2]


def source_link(path, line, label):
    return f"[{label}](../{path}#L{line})"


def render():
    version = (ROOT / "THEORY_VERSION").read_text().strip()
    review = f"data/publication/v{version}/verdict.json"
    verdict = json.loads((ROOT / review).read_text())
    register = json.loads((ROOT / f"data/publication/v{version}/register.json").read_text())["groups"]
    profile_summaries = {row["rg_id"]: row["profile_summary"] for row in register if row.get("profile_summary")}
    catalog = json.loads((ROOT / "specs/proof_scope.json").read_text())["groups"]
    requirements_path = "TDN/Requirements/MscRequirements.lean"
    shared = "TDN/Requirements/CsfcRoleObligations.lean"
    definitions = {match[1]: i for i, line in enumerate((ROOT / requirements_path).read_text().splitlines(), 1)
                   if (match := re.match(r"def (\w+)", line))}
    clauses = {}
    in_catalog = False
    for i, line in enumerate((ROOT / shared).read_text().splitlines(), 1):
        if line.startswith("def ComplianceContext.RequirementGroupSpec "):
            in_catalog = True
        if line.startswith("def ComplianceContext.ComponentApplies "):
            break
        if in_catalog and (match := re.match(r"  \| (\d+) =>", line)):
            clauses[int(match[1])] = i
    selected = [row for row in catalog if row["decision"] == "formal"]
    other = [row for row in catalog if row["decision"] != "formal"]
    reviewed = set(verdict["reviewed_RGs"])
    assert set(definitions) == {g["specification"].split(".")[-1] for g in selected}
    assert set(clauses) == {int(g["id"][3:]) for g in catalog}
    assert {g["id"] for g in selected} == set(verdict["selected_RGs"])
    summary = (f"TDN v{version} selects {len(selected)} of the {len(catalog)} CSfC requirement groups for proof. "
               f"{len(reviewed)} have reviewed complete proofs under their recorded model assumptions.")
    if "RG-008" in verdict["deferred_RGs"]:
        summary += " RG-008 has checked proofs of plaintext delivery within the source security level. Its complete specification remains open."
    lines = [
        "# Requirement groups and their Lean formalizations", "", summary, "",
        "The [proof scope](proof_scope.json) identifies the selected groups. "
        f"The [review record](../{review}) identifies which proofs passed review. "
        "The [clause guide](requirement_clauses.md) links individual passages to their Lean conditions, examples and assumptions.", "",
        f"## {len(selected)} proof targets", "",
        "| RG | Requirement | Top-level Lean specification | Proof status |",
        "| --- | --- | --- | --- |",
    ]
    for g in selected:
        name = g["specification"].split(".")[-1]
        status = "Complete model proof reviewed" if g["id"] in reviewed else "Supporting proofs only"
        if g["id"] in profile_summaries:
            status += ". " + profile_summaries[g["id"]]
        lines.append(f'| [{g["id"]}](requirement_groups.md#{g["id"].lower()}) | {g["title"]} | '
                     f'{source_link(requirements_path, definitions[name], name)} | {status} |')
    lines.extend(["", f"## {len(other)} other catalog requirements", "",
                  "Each group keeps its original CSfC text and its place in the shared catalog. "
                  "RG-008 refers to this catalog when it requires included networks to satisfy their applicable duties. "
                  "A catalog entry can supply a condition to another proof. Its presence does not establish compliance.", "",
                  "| RG | Requirement | Catalog condition | Treatment |", "| --- | --- | --- | --- |"])
    treatment = {"check": "Direct check of recorded facts", "external": "External evidence",
                 "scope": "Permission or applicability", "catalog": "Catalog only"}
    for g in other:
        n = int(g["id"][3:])
        action = g["action"] if g["decision"] == "catalog" else treatment[g["decision"]]
        lines.append(f'| [{g["id"]}](requirement_groups.md#{g["id"].lower()}) | {g["title"]} | '
                     f'{source_link(shared, clauses[n], f"Case {n}")} | {action} |')
    lines.extend(["", "The shared function takes the deployment, the component or network being assessed, and the group number. "
                  "Cases 70 and 74 add no separate condition. For RG-074, assess redundant devices under the existing duties for their roles. "
                  "The [source catalog](requirement_groups.md) retains the complete text, including conditions involving external evidence.", ""])
    return "\n".join(lines)


def render_scope(original):
    version = (ROOT / "THEORY_VERSION").read_text().strip()
    directory = ROOT / "data/publication" / f"v{version}"
    verdict = json.loads((directory / "verdict.json").read_text())
    reviewed = set(verdict["reviewed_RGs"])
    selected = set(verdict["selected_RGs"])
    if reviewed | set(verdict["deferred_RGs"]) != selected:
        raise ValueError("Review verdict omits or adds a requirement")
    rg8 = json.loads((ROOT / verdict["review_records"]["RG-008"]).read_text())["profile_outcomes"]
    lines = ["<!-- BEGIN review status -->",
             f"TDN v{version} selects {len(selected)} requirement groups. General proofs for {len(reviewed)} have passed review under their stated assumptions.", ""]
    for profile, outcome in rg8.items():
        if outcome["outcome"] == "SATISFIES":
            text = "satisfies the full connectivity requirement"
        elif outcome["outcome"] == "VIOLATES" and outcome.get("scoped_forwarding_proof"):
            pair = " and ".join(f'`{name}`' for name in outcome["component_pair"])
            text = f"preserves forwarding isolation and violates the inherited physical-separation duty because {pair} share a host"
        else:
            raise ValueError(f"Unrecognized RG-008 profile result for {profile}")
        lines.append(f"- The {profile} deployment {text}. Lean checks {outcome['positive_paths']} intended delivery paths.")
    lines.extend(["", f"[Current verdict](../data/publication/v{version}/verdict.json). "
                  "[Source clauses, interpretations and evidence](../specs/requirement_clauses.md).",
                  "<!-- END review status -->"])
    updated, count = re.subn(r"<!-- BEGIN review status -->.*?<!-- END review status -->",
                             "\n".join(lines), original, flags=re.S)
    if count != 1:
        raise ValueError("Expected one generated review status section")
    return updated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if any generated map or scope summary is stale")
    args = parser.parse_args()
    scope = ROOT / "docs/theory_scope.md"
    outputs = {ROOT / "specs/requirement_formalizations.md": render(),
               ROOT / "specs/requirement_clauses.md": render_clauses(),
               scope: render_scope(scope.read_text())}
    for path, value in outputs.items():
        if not path.exists() or path.read_text() != value:
            if args.check:
                raise SystemExit(f"Stale {path.relative_to(ROOT)}. Run {Path(__file__).relative_to(ROOT)}.")
            path.write_text(value)

if __name__ == "__main__":
    main()
