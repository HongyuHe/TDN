"""Render case-level results for the active three-network comparison."""

from collections import Counter
from html import escape
from pathlib import Path
import json

from cohort import HERE, NETWORKS, SNAPSHOT_RUN, require_current_run
from score_trials import summarize
from run_series import plan


def qualification_panel(root):
    from architecture_cases import FAMILIES

    ledger = root.parent / "multilevel-qualification-verified" / "summary.json"
    if not ledger.is_file():
        return ""
    source = json.loads(ledger.read_text())
    seen = {(r["family"], r["network"]) for r in source["cases"]}
    if (
        seen != {(f, n) for n in NETWORKS for f in FAMILIES}
        or len(source["cases"]) != len(seen)
        or source["networks"] != list(NETWORKS)
        or Path(source["clean_controls"]).resolve() != root.resolve()
        or any(r["lean"] != ["pass", "rejected", "pass"] for r in source["cases"])
    ):
        raise ValueError(
            "The qualification ledger differs from the registered experiment"
        )
    rows = []
    labels = {
        "shared-inner-gateway": "RG-008.01 · Shared Inner gateway",
        "gray-cross-level-path": "RG-013.01 · Path around the Gray Firewall",
        "gray-cross-level-forward": "RG-040.02 · Gray Firewall forwards across levels",
    }
    for record in source["cases"]:
        facts = record["measurement"]
        if record["family"] == "shared-inner-gateway":
            detail = " · ".join(
                f"{s['source']} on {s['gateway']} increased from {s['before']} to {s['after']} encrypted packets"
                for s in facts
            )
        elif record["family"] == "gray-cross-level-path":
            detail = " → ".join(facts["path"])
        else:
            packet = facts["ingress"][0]
            detail = f"{packet['source']} → {packet['destination']}, identical ESP bytes on {packet['iface']} and {facts['egress'][0]['iface']}"
        url = (Path(record["trial"]) / "independent-evidence.json").as_uri()
        rows.append(
            f'<tr><th>{escape(labels[record["family"]])}</th><td>{escape(record["network"])}</td><td><a href="{escape(url)}">{escape(record["device"])}</a></td><td>{escape(detail)}</td></tr>'
        )
    return f'<section id="implementation"><h2>Live implementation checks</h2><p>Each replacement was exercised on all three replicas. Lean accepted the clean controls, rejected the intended clause on each faulty snapshot and accepted the restored configurations. The comparison table counts reviewed detector trials separately.</p><div class="table"><table><tr><th>Replacement</th><th>Network</th><th>Observed device</th><th>Measured effect</th></tr>{"".join(rows)}</table></div></section>'


def build(root, destination):
    require_current_run(root)
    scores = summarize(root)
    paired_root = SNAPSHOT_RUN
    paired = None
    if (paired_root / "score.json").exists():
        require_current_run(paired_root)
        published = json.loads((paired_root / "score.json").read_text())
        if published["source_run"] == root.name:
            paired = published
    observations = {(r["type"], r["network"]): r for r in scores["rows"]}
    repeats = (
        {(r["type"], r["network"]): r["new"] for r in paired["rows"]} if paired else {}
    )
    planned = list(plan())
    descriptions = json.loads((HERE / "violation_descriptions.json").read_text())
    names = {"astra": "Astra", "sol": "Sol", "tdn": "TDN"}
    columns = [(m, names[m] + " · live") for m in ("astra", "sol")] + [
        ("tdn", "TDN · snapshot")
    ]
    columns += [(m + "-snap", names[m] + " · snapshot") for m in ("astra", "sol")]
    heads = "".join(f"<th>{escape(label)}</th>" for _, label in columns)
    bodies = []
    counts = {key: Counter() for key, _ in columns}
    type_results = {key: [] for key, _ in columns}
    for family, definition in scores["types"].items():
        details = descriptions[family]["variants"]
        body = []
        cells = {key: [] for key, _ in columns}
        for f, n in planned:
            if f != family:
                continue
            case = observations.get((f, n), {})
            methods = {
                **case.get("methods", {}),
                **{m + "-snap": v for m, v in repeats.get((f, n), {}).items()},
            }
            fields = []
            for key, _ in columns:
                entry = methods.get(key, {})
                verdict = entry.get("verdict", "pending")
                counts[key][verdict] += 1
                cells[key].append(verdict)
                elapsed = entry.get("seconds")
                timing = (
                    "" if elapsed is None else f"<br><small>{elapsed:.2f} s</small>"
                )
                fields.append(
                    f'<td class="{escape(verdict)}">{escape(verdict)}{timing}</td>'
                )
            body.append(f"<tr><th>{escape(n)}</th>{''.join(fields)}</tr>")
        for key, values in cells.items():
            if len(values) == len(NETWORKS) and "pending" not in values:
                type_results[key].append(all(v == "hit" for v in values))
        description = "".join(
            f"<p>{escape(v['requirement'])} {escape(v['change'])}</p>" for v in details
        )
        clauses = ", ".join(definition["clause_ids"])
        bodies.append(
            f'<section id="{escape(family)}"><h2>{escape(clauses)} · {escape(definition["title"])}</h2>{description}'
            f'<div class="table"><table><thead><tr><th>Network</th>{heads}</tr></thead>'
            f"<tbody>{''.join(body)}</tbody></table></div></section>"
        )
    summary_rows = []
    for key, label in columns:
        reviewed = len(planned) - counts[key]['pending']
        cases = f"{counts[key]['hit']}/{reviewed}" if reviewed else "Pending"
        completed_types = type_results[key]
        types = f"{sum(completed_types)}/{len(completed_types)}" if completed_types else "Pending"
        summary_rows.append(f"<tr><th>{escape(label)}</th><td>{cases}</td><td>{types}</td><td>{counts[key]['pending']}</td></tr>")
    summary = "".join(summary_rows)
    links = "".join(
        f'<a href="#{escape(family)}">{escape(" / ".join(d["clause_ids"]))}</a>'
        for family, d in scores["types"].items()
    )
    qualifications = qualification_panel(root)
    qualification_link = (
        '<a href="#implementation">Implementation checks</a>' if qualifications else ""
    )
    doc = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TDN · Three-network baseline</title><style>
body{{font:16px/1.5 system-ui;color:#192535;max-width:66rem;margin:auto;padding:1.3rem}}
nav{{position:sticky;top:0;background:white;padding:.5rem;border-bottom:1px solid #b7c1ce;z-index:1}} nav a{{display:inline-block;margin-right:.9rem}}
section{{scroll-margin-top:6rem}} h1,h2{{line-height:1.2}}h2{{margin-top:2rem}}table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:.45rem .65rem;border-bottom:1px solid #d1d8e0}}.table{{overflow-x:auto}}.hit{{color:#075f47}}.miss,.timeout{{color:#9b3437}}
@media(max-width:700px){{nav{{white-space:nowrap;overflow-x:auto}}table{{font-size:.88rem}}}}</style>
<h1>CSfC compliance on three multi-level networks</h1>
<p>Each of {len(scores["types"])} faults is tested separately on {", ".join(NETWORKS)}.
{len(observations)} of {len(planned)} live cases have reviewed results. A type earns credit when the method detects it on all {len(NETWORKS)} networks.</p>
<nav aria-label="Fault types"><a href="#results">Results</a>{qualification_link}{links}</nav>
<section id="results"><h2>Detections</h2><div class="table"><table><tr><th>Method and evidence</th><th>Cases detected / reviewed</th>
<th>Types detected / reviewed on all three networks</th><th>Pending cases</th></tr>{summary}</table></div>
<p>Live detectors inspect the running networks. Snapshot detectors inspect the saved observations. TDN checks the affected snapshot.
Detector times cover the audit. TDN times cover Lean typechecking after data import. A pending entry awaits measurement or review.</p></section>
{qualifications}{"".join(bodies)}</html>"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(doc)
    return destination
