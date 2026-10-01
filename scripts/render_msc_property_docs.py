#!/usr/bin/env python3
"""Render individual CSfC assessments without rewriting the source inventory."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/CSfC_network_properties.md"
SCOPE = ROOT / "models/msc_requirement_scope.json"
PROVABLE = ROOT / "docs/CSfC_network_provable_properties.md"
UNPROVABLE = ROOT / "docs/CSfC_network_unprovable_properties.md"
ENTRY_PATTERN = re.compile(
    r"^#{3,4} ((?:MSC-[A-Z]+-\d+|(?:N|ISSUE|DEP)-\d+))([^\n]*)\n"
    r"(.*?)(?=^#{1,4} |\Z)",
    re.M | re.S,
)

#* Preserve the names and order in CP Table 3, including annex-only categories.
REQUIREMENT_CATEGORIES = [
    ("PS", "Product Selection Requirements"),
    ("SR", "Overall Solution Requirements"),
    ("VG", "VPN Gateway Requirements"),
    ("MD", "MACsec Device Requirements"),
    ("AA", "Certificate-based MACsec Authentication and Authorization Requirements"),
    ("IR", "Additional Requirements for Inner Encryption Components"),
    ("OR", "Additional Requirements for Outer Encryption Components"),
    ("PF", "Port Filtering Requirements for Solution Components"),
    ("CM", "Configuration Change Detection Requirements"),
    ("DM", "Device Management Requirements"),
    ("MR", "Continuous Monitoring Requirements"),
    ("AU", "Auditing Requirements"),
    ("GD", "Use and Handling of Solutions Requirements"),
    ("RP", "Incident Reporting Requirements"),
    ("RB", "Role-Based Personnel Requirements"),
    ("TR", "Testing Requirement"),
    ("KM", "Key Management Requirements"),
]
ANNEX_CATEGORIES = {"CM", "MR", "AU", "KM"}


def category_counts(scope):
    """Count source requirements once, independently of their number of theorems."""
    result = []
    for code, name in REQUIREMENT_CATEGORIES:
        rows = [row for row in scope["entries"] if row["id"].startswith(f"MSC-{code}-")]
        active = [row for row in rows if row["source_status"] == "Active"]
        retained = [row for row in active if row["assessment_scope"] != "excluded_management"]
        checked = sum(bool(row["theorems"]) for row in retained)
        result.append({"code": code, "name": name, "listed": len(rows), "active": len(active),
                       "excluded": len(active) - len(retained), "denominator": len(retained),
                       "checked": checked, "unchecked": len(retained) - checked})
    return result


def category_summary(scope):
    rows = category_counts(scope)
    totals = {key: sum(row[key] for row in rows)
              for key in ["listed", "active", "excluded", "denominator", "checked", "unchecked"]}

    def fraction(count, denominator):
        return f"{count}/{denominator} ({100 * count / denominator:.1f}%)" if denominator else "N/A"

    lines = [
        "## Coverage by Table 3 category",
        "",
        "**Coverage (partial)** counts requirements with at least one Lean theorem proving the specific claim stated in their assessment.",
        "A checked claim may cover part of a requirement or its modeled behavior; it does not establish the complete real-world requirement.",
        "Each percentage uses the category's active numbered requirements after excluding management-only requirements as its denominator.",
        "Relocated and withdrawn rows remain in the listed counts but are excluded from the percentages.",
        "Mixed requirements remain in the denominator and are assessed only for their retained clauses.",
        "",
        "| Category | Listed rows | Active rows | Management excluded | Coverage (partial) |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        if row["code"] in ANNEX_CATEGORIES and not row["listed"]:
            lines.append(f'| **{row["code"]}**: {row["name"]} | 0 represented | N/A | N/A | N/A |')
            continue
        counts = fraction(row["checked"], row["denominator"])
        lines.append(f'| **{row["code"]}**: {row["name"]} | {row["listed"]} | {row["active"]} | {row["excluded"]} | {counts} |')
    counts = fraction(totals["checked"], totals["denominator"])
    lines.extend([
        f'| **Total represented requirements** | **{totals["listed"]}** | **{totals["active"]}** | **{totals["excluded"]}** | {counts} |',
        "",
        f'The coverage column reports each category\'s covered count, retained active count, and percentage; its numerator gives the category\'s raw contribution to the {totals["checked"]} partially covered requirements.',
        "A requirement with several theorems is counted once.",
        "The total percentage is computed from total counts, rather than averaging category percentages.",
        "Requirements without a checked contribution include unselected alternatives and unmet evidence obligations; absence of coverage does not mean a requirement is violated or inherently unprovable.",
        "CM, MR, AU, and KM refer to separate annexes in Table 3; those annex requirements are absent from the supplied inventory, so their totals and percentages are unavailable rather than zero coverage.",
        "Narrative entries and source/dependency annotations are excluded from the category counts because they are not additional numbered requirements.",
    ])
    return "\n".join(lines)


def inventory_entries(text):
    """Keep every original word and internal line break, including metadata."""
    return [
        {"id": match[1], "heading_suffix": match[2], "body": match[3].strip()}
        for match in ENTRY_PATTERN.finditer(text)
    ]


def theorem_sources():
    result = {}
    for path in (ROOT / "TDN/MSC").glob("*.lean"):
        for name in re.findall(r"^theorem (\w+)", path.read_text(), re.M):
            if name in result:
                raise ValueError(f"duplicate theorem name: {name}")
            result[name] = path.relative_to(ROOT).as_posix()
    return result


def prose(text):
    """Break between sentences only; never hard-wrap a sentence."""
    return re.sub(r"(?<=[.!?]) (?=[A-Z`])", "\n", text)


def quote_entry(entry):
    #* Marker pairs allow an independent test to recover the verbatim quotation.
    quoted = "\n".join(
        "> " + line if line else ">" for line in entry["body"].splitlines()
    )
    return (
        f'<!-- inventory: {entry["id"]} -->\n'
        f"{quoted}\n"
        f'<!-- /inventory: {entry["id"]} -->'
    )


def linked_theorems(row, sources):
    return ", ".join(f"[`{name}`](../{sources[name]})" for name in row["theorems"])


def header(scope, checked):
    count = sum(bool(row["theorems"]) for row in scope["entries"])
    excluded = sum(row["assessment_scope"] == "excluded_management" for row in scope["entries"])
    if checked:
        title = "# CSfC properties with individual checked model contributions"
        purpose = f"""Each entry below quotes one inventory entry word for word and identifies its existing Lean proof contribution within the selected experiment.
No P/U summary combines several source properties.
The {count} entries have checked model contributions; none is presented as a certificate of the complete real-world requirement.
The companion [assessment register](CSfC_network_unprovable_properties.md) lists all 293 inventory entries separately, including these {count} and their scope limits.
An entry appears in both documents so its checked claim can be read alongside its full source wording.
An entry's absence from this document means that no corresponding checked contribution is identified here, not that the property is inherently unprovable."""
    else:
        title = "# CSfC properties: individual assessments, exclusions, and remaining gaps"
        purpose = f"""Every inventory entry receives its own verbatim quotation and scoped node-1 assessment below.
The register contains 214 numbered entries, 57 narrative entries, 13 source-issue annotations, and 9 dependency annotations.
The numbered entries comprise 194 active rows, 15 relocated rows, and 5 withdrawn rows.
Those counts do not mean 293 simultaneous mandatory obligations or 293 failed requirements.
Permissions, definitions, unselected alternatives, conditional branches, and source annotations retain their original meaning.
The companion [checked-contributions document](CSfC_network_provable_properties.md) gives the exact existing Lean claim for each of the {count} entries with a retained proof contribution.
The {excluded} management-only entries marked outside the experiment are neither failed properties nor requirements proved by removing their subjects.
The historical filename does not mean that every entry in the register is unprovable."""
    return title + "\n\n" + category_summary(scope) + "\n\n" + purpose + "\n\n" + """## Selected experiment: management devices and traffic excluded

The assessment assumes that administrative workstations and their network traffic are absent from the MSC experiment.
The projection excludes the six `AW_*` containers, the six dedicated `M_*` management switches, all 20 management cables, and management interfaces, services, and sessions on the retained appliances.
The retained topology has 23 logical devices and 24 Red, Gray, or Black cables.
Worker SSH, `twinet msc console`, and `docker exec` are trusted experiment controls outside the packet model.
The reasoning concerns a fixed configuration; it does not include an operator changing rules or injecting packets during a modeled execution.

Management-only requirements are outside the experiment and impose no proof obligation on its data-path claims.
Mixed entries are assessed only for their retained data, tunnel, trust, or control clauses.
Management traffic supplies neither a counterexample nor a missing coverage obligation for OR-4 or the nested-encryption claim.
Necessary control traffic remains in scope under its stated exceptions, including IKE and Black-underlay OSPF.
Tunnel authentication, key protection, revocation, and appliance time synchronization are not removed merely because some source text uses the word “management.”

The exclusion is an explicit research scope choice.
N-28 still records that complete MSC solutions require Red and Gray AWs; the inventory's wording is preserved.
An excluded obligation is not asserted to be optional in the CP, satisfied vacuously, or proved by the experiment.
The assessment makes no whole-solution compliance claim.

The pinned export retains its original management devices.
Required Lean regeneration projects out optional management before checking device evidence and emits 23 devices and 24 cables.
The retained counts are checked by Lean; unavailable or misconfigured optional management cannot block required regeneration.
HistoricalDeployment.lean and SnapshotDiagnostics.lean preserve the full export and its seven diagnostics behind explicit generation and import.
The existing data-path results concern unchanged Red/Gray/Black edges, retained appliance FORWARD rules, or protected-Red packet operations.
They do not require the management graph invariants or the HTTPS management probes as premises.
Full-snapshot count and observation theorems are identified as historical evidence where cited; their management portions are not added obligations for the projection.

## Evidence and interpretation

The assessment uses the [source inventory](CSfC_network_properties.md) and the supplied [MSC CP v1.3.0 PDF](CSfC_documentation_v1.3.0.pdf), dated 27 March 2026.
Each blockquote preserves the entire inventory entry, including applicability, alternatives, source references, and extraction caveats.
Narrative, ISSUE, and DEP identifiers are inventory annotations rather than official numbered requirements.
The review compared all 214 numbered descriptions with independently extracted PDF table cells.
Of those descriptions, 213 match after whitespace normalization; VG-19 contains displaced underscores in its exchange names.
VG-19's assessment records the PDF spelling without silently changing the inventory quotation.
Threshold/objective choices, permissions, conditions, and source conflicts are retained rather than collapsed into unconditional rules.

The node-1 evidence is the [reviewed export](../artifacts/msc-node1-reviewed/snapshot/manifest.json) collected on 1 October 2026 from 19:37:31 to 19:37:55 UTC after the gateway protocol and IPv4-options guards were deployed.
The [probe report](../artifacts/msc-node1-reviewed/check.json) precedes that export and records 273 passing checks; the observations are not atomic.
Additional [live guard probes](../artifacts/msc-lean-review/deployment-hardening/guard-probes.json) check protocol rejection at all four inner gateways and option rejection with a positive control at all four outer gateways.
The [original September export](../artifacts/msc-node1-model/snapshot/manifest.json) remains unchanged for explicitly historical diagnostics and the original Datalog/ASP comparison.
The full evidence snapshot has 35 logical devices and 44 virtual cables, including the excluded management infrastructure.
The selected experiment retains two sites, two unordered security labels, IPsec at both layers, IPv4, separate Gray segments, and separate outer encryptors per level.
The assessment concerns the recorded October observation interval and does not assert that future live state will remain identical.
Intended strongSwan files record configuration intent; sampled SAs and certificate listings record observed runtime facts.
Neither type of evidence is silently substituted for the other.

The [importer](../scripts/import_msc_snapshot.py) validates evidence hashes and translates selected fields into [Deployment.lean](../TDN/MSC/Deployment.lean).
The [topology model](../TDN/MSC/Topology.lean) reasons about imported virtual cables and declarations.
The [policy model](../TDN/MSC/Policy.lean) represents a restricted IPv4 FORWARD-rule subset, including the exact supported header-length guard for rejecting IPv4 options.
It omits INPUT, OUTPUT, NAT, fragment and malformed-packet processing, IPv6, and OVS switching semantics.
The [flow model](../TDN/MSC/Flow.lean) represents protected Red payloads using symbolic wrappers and explicit readiness/authentication assumptions.
Those wrappers prove processing order, not cryptographic secrecy or Linux/strongSwan correctness.
Evidence completeness, correct translation, real packet identity, and implementation fidelity remain explicit boundaries when applying model results to the deployment.

The double-encryption scope is classified data crossing the untrusted network, as stated in Section 4 on printed page 3 / PDF page 10.
OR-4 explicitly excepts control-plane traffic on Gray ingress, and PF-3 permits IKE/ESP and approved control traffic on Black-facing VPN interfaces.
Permitted control packets are therefore not counterexamples to the specified data-protection claim.
Within the selected scope, the remaining OR-4 gap is coverage of all retained non-control Gray ingress and its relation to actual packet processing.
Management traffic is excluded and creates no additional gap.
The assessment does not assume arbitrary hostile access to trusted Gray and then call that unprovided threat assumption a CP violation.

## Reading the assessments

“Checked model contribution” identifies an existing theorem and its exact restricted claim.
“Outside experiment: management excluded” records a scope exclusion, not a failed requirement.
“Retained clauses only; management excluded” identifies a mixed source statement whose management clauses do not affect its retained claim.
“Configuration evidence” identifies observed or intended facts that have not yet been turned into a complete theorem.
“Model or evidence gap” means that additional semantics, policy, or observations are needed; Lean's expressiveness is not the limiting claim.
“Not enforced or contradicted” identifies a specific implementation mismatch rather than a mere lack of proof.
“Conditional or unselected alternative” does not count an inactive branch as a failed obligation.
External approvals, physical conditions, and human actions require evidence beyond the packet/topology model.
Default-deny forwarding proves a negative restriction but does not prove a separate obligation to allow required services.

The [machine-readable review](../models/msc_requirement_scope.json) stores every individual assessment and its theorem/evidence references.
Run `python3 scripts/render_msc_property_docs.py --check` from the repository root to check that both documents match that review and the unchanged inventory.
"""


def section(identifier):
    if identifier.startswith("MSC-"):
        return "Numbered requirements: " + identifier.split("-")[1]
    return {
        "N": "Narrative inventory entries",
        "ISSUE": "Source-issue annotations",
        "DEP": "Dependency annotations",
    }[identifier.split("-")[0]]


def render(scope, entries, checked):
    sources = theorem_sources()
    rows = {row["id"]: row for row in scope["entries"]}
    if len(rows) != len(entries) or set(rows) != {entry["id"] for entry in entries}:
        raise ValueError("inventory/review identifiers differ or contain duplicates")
    parts = [header(scope, checked)]
    previous_section = None
    for entry in entries:
        identifier = entry["id"]
        row = rows[identifier]
        if checked and not row["theorems"]:
            continue
        for name in row["theorems"]:
            if name not in sources:
                raise ValueError(f"{identifier}: nonexistent theorem {name}")
        current_section = section(identifier)
        if previous_section != current_section:
            parts.append("## " + current_section)
            previous_section = current_section
        parts.extend([
            f'<a id="{identifier.lower()}"></a>\n\n### {identifier}{entry["heading_suffix"]}',
            "**Inventory entry, verbatim:**",
            quote_entry(entry),
            f'**Assessment scope:** {scope["scope_labels"][row["assessment_scope"]]}.',
            f'**Assessment within the selected scope:** {row["disposition"]}.',
        ])
        if checked:
            parts.extend([
                "**Exactly what is proved:**\n\n" + prose(row["model_claim"]),
                "**Existing Lean theorems:** " + linked_theorems(row, sources) + ".",
                "**Scope and remaining limits:**\n\n" + prose(row["reason"]),
                f'**Companion entry:** [{identifier} scoped assessment](CSfC_network_unprovable_properties.md#{identifier.lower()}).',
            ])
        else:
            parts.append("**Node-1 reasoning:**\n\n" + prose(row["reason"]))
            if row["theorems"]:
                parts.append(f'**Checked contribution:** [{identifier}: exact model claim and theorem links](CSfC_network_provable_properties.md#{identifier.lower()}).')
            elif row["assessment_scope"] == "excluded_management":
                parts.append("**Proof obligation in this experiment:** None; the management requirement is excluded, not proved.")
            else:
                parts.append("**Existing Lean proof of this entry:** None identified; configuration evidence or an inactive condition is not labeled a checked theorem.")
        links = []
        for key in row["evidence"]:
            label, path = scope["evidence_catalog"][key]
            if not (ROOT / path).is_file():
                raise ValueError(f"missing evidence file: {path}")
            links.append(f"[{label}](../{path})")
        parts.append("**Evidence and model boundary:** " + "; ".join(links) + ".")
    if checked:
        used = {name for row in rows.values() for name in row["theorems"]}
        excluded_theorems = scope["excluded_theorems"]
        unused = sorted(set(sources) - used - set(excluded_theorems))
        if unused:
            parts.extend([
                "## Supporting theorem outside the source obligations",
                "The following model result remains useful, but no new CP property is invented to accommodate it.",
                "\n".join(f"- [`{name}`](../{sources[name]}): modeled transport failure blocks transmission; the result is conditional behavior, not a CP availability guarantee." for name in unused),
            ])
        parts.extend([
            "## Existing management theorems outside this assessment",
            "The following theorems remain in the original Lean model, but supply no proof contribution or prerequisite for the selected experiment.",
            "\n".join(f"- [`{name}`](../{sources[name]}): {reason}" for name, reason in excluded_theorems.items()),
        ])
    return "\n\n".join(part.strip() for part in parts).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify output without changing files")
    args = parser.parse_args()
    scope = json.loads(SCOPE.read_text())
    if hashlib.sha256(INVENTORY.read_bytes()).hexdigest() != scope["review"]["inventory_sha256"]:
        raise SystemExit("inventory changed since review; reassess changed entries before rendering")
    entries = inventory_entries(INVENTORY.read_text())
    mismatched = []
    for path, checked in [(PROVABLE, True), (UNPROVABLE, False)]:
        expected = render(scope, entries, checked)
        if args.check:
            if not path.exists() or path.read_text() != expected:
                mismatched.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(expected)
    if mismatched:
        raise SystemExit("stale generated documents: " + ", ".join(mismatched))
    counts = Counter(section(entry["id"]) for entry in entries)
    print(f"{'Verified' if args.check else 'Rendered'} {len(entries)} individual entries across {len(counts)} inventory sections.")


if __name__ == "__main__":
    main()
