"""Render the independently reviewed 20-by-3 study and link each conclusion to its evidence."""

import argparse
import html
import json
from math import sqrt
import os
from pathlib import Path
from statistics import median
import sys
from urllib.parse import quote

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
from scale.catalog import CHANGES
from scale.design import CONTROLS, PANEL_REVISION, VERSION, cases_for, clause_coverage, control_run_root, controls_for
from scale.profiles import NETWORKS, inventory


def load(p):
    return json.loads(p.read_bytes()) if p.is_file() else {}


def esc(s):
    return html.escape(str(s), quote=True)


def seconds(t):
    if t is None:
        return "—"
    return f"{t:.2f} s" if t < 1 else (f"{t:.1f} s" if t < 60 else f"{t / 60:.1f} min")


def read_cell(root, net, case):
    base = root / "measurements" / net / case.key
    truth = load(base / "cell.json")
    detector = root / "trials" / case.key / net / "astra"
    sess = load(detector / "execution.json")
    checks = load(base / "tdn/verification.json")
    ast = load(base / "astra-adjudication.json")
    tdn = load(base / "tdn-adjudication.json")
    durations = [v.get("typecheck_ns") for v in checks.values()]
    elapsed = sum(x for x in durations if x is not None) / 1e9 if durations else None
    return {
        "net": net,
        "key": case.key,
        "observed": truth.get("observed"),
        "bundle": truth.get("bundle"),
        "astra": ast.get("decision", sess.get("status", "pending")),
        "tdn": tdn.get("decision", "pending"),
        "astra_seconds": sess.get("duration_seconds"),
        "tdn_seconds": elapsed,
        "timed_files": sum(v is not None for v in durations),
        "total_files": len(checks),
        "queries": sess.get("reader_calls"),
        "reason": ast.get("explanation", ""),
        "quote": ast.get("quotation", ""),
        "anchor": truth.get("anchor"),
        "level": truth.get("level"),
        "control_variant": truth.get("control_variant"),
        "observation": truth.get("location_evidence"),
        "tdn_reason": tdn.get("explanation", ""),
        "findings": ast.get("findings") if ast.get("complete") else None,
        "rejected": [k for k, v in checks.items() if v["status"] in {"rejected", "proof_error"}],
        "diagnostics": {
            k: v["status"]
            for k, v in checks.items()
            if v["status"] not in {"pass", "rejected", "proof_error"}
        },
    }


def alert_statistics(reviews):
    reviewed = [r for r in reviews if r.get("complete") and isinstance(r.get("findings"), list)]
    clean = [r for r in reviewed if r["case"] in CONTROLS]
    findings = [f for r in reviewed for f in r["findings"]]
    counts = {key:sum(f["classification"] == key for f in findings)
              for key in ("target","consequence","other_real","false_positive","unresolved")}
    return {"reviewed_sessions": len(reviewed), "reviewed_clean": len(clean), "findings": counts,
            "clean_with_any_alert": sum(bool(r["findings"]) for r in clean),
            "clean_with_false_alarm": sum(any(f["classification"] == "false_positive" for f in r["findings"])
                                          for r in clean)}


def wilson_interval(count, total):
    if not total:
        return None
    z = 1.959963984540054
    rate = count/total
    denom = 1 + z*z/total
    middle = (rate + z*z/(2*total))/denom
    radius = z*sqrt(rate*(1-rate)/total + z*z/(4*total**2))/denom
    return max(0,middle-radius), min(1,middle+radius)


CSS = """
:root{color-scheme:light;--ink:#182b3c;--muted:#465d6c;--line:#cbd8de;--paper:#fff;--bg:#f4f7f7;--astra:#48468b;--tdn:#006553}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:20px}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}.shell{max-width:1350px;margin:auto;padding:32px;display:grid;grid-template-columns:170px minmax(0,1fr);gap:30px}nav{align-self:start;position:sticky;top:20px;border-left:2px solid var(--line);padding-left:15px}nav a{display:block;margin:9px 0;color:var(--ink);font-size:14px}main{min-width:0}a{color:#075d77;text-underline-offset:3px}h1,h2,h3,p{margin:0 0 .7em}h1{font-size:clamp(32px,4.1vw,54px);line-height:1.04;letter-spacing:-.048em;max-width:21ch}h2{font-size:27px;line-height:1.15;letter-spacing:-.025em}h3{font-size:18px}header,section{padding:27px 30px;background:var(--paper);border:1px solid var(--line);border-radius:13px;margin-bottom:20px}.kicker{color:#096953;font-size:13px;font-weight:700;letter-spacing:.045em;text-transform:uppercase}.lead{font-size:19px;max-width:66ch;color:#304a59}.fine,.evidence{font-size:14px;color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.card{border:1px solid var(--line);padding:14px;border-radius:8px}.large{font-size:31px;font-weight:720;letter-spacing:-.04em}.bar{display:grid;grid-template-columns:6ch minmax(0,1fr) 6ch;gap:7px;font-size:13px;margin:7px 0;align-items:center}.track{background:#e5ebeb;border-radius:6px;height:9px}.fill{height:100%;background:var(--astra);border-radius:inherit}.tdn .fill{background:var(--tdn)}.tag{font-size:12px;font-weight:650}.yes{color:#005947}.no{color:#a03838}.pending{color:#596b74}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:9px 7px;border-bottom:1px solid var(--line);vertical-align:top}th{font-weight:650;background:#f3f6f7}.code{font:12px ui-monospace,monospace;color:#485d6b}details{border-top:1px solid var(--line);padding:11px 0}summary{cursor:pointer;font-weight:620}.quote{border-left:3px solid #b6b5d7;padding-left:13px;color:#34495d}.pair{white-space:nowrap}.pill{padding:3px 6px;border-radius:4px;font-size:12px;font-weight:680}.hit{color:#005947;background:#e1f3eb}.miss{color:#922c36;background:#f9e7e8}.wait{color:#4a5b63;background:#edf1f1}footer{font-size:13px;color:var(--muted)}@media(max-width:950px){.shell{grid-template-columns:1fr;padding:12px;gap:12px}nav{z-index:2;top:0;background:#fafcfc;border:1px solid var(--line);border-radius:7px;padding:6px 10px;display:flex;gap:15px;overflow:auto}nav a{white-space:nowrap;margin:3px 0}.cards{grid-template-columns:1fr}section,header{padding:20px}.scroll{max-width:100%}}@media print{nav{display:none}.shell{display:block}section,header{break-inside:avoid;border:none}}
"""


def build(root, out, preview=False):
    root = root.resolve()
    out = out.resolve()
    protocol = load(root/"protocol.json")
    cases = cases_for(protocol)
    controls = controls_for(protocol)
    current = protocol.get("method_version") == VERSION
    matched_variants = protocol.get("panel_revision") == PANEL_REVISION
    revised = protocol.get("method_version") in (2,VERSION)
    cells = {(c.key, n): read_cell(root, n, c) for c in cases for n in NETWORKS}
    reviews = [load(p) for p in sorted((root/"measurements").glob("*/*/astra-adjudication.json"))]
    alerts = alert_statistics(reviews)
    judged = {"detected", "missed"}
    if not preview:
        if revised:
            from scale.panel import approved_panel
            approved_panel(root, for_execution=False)
        pending = [
            (c["net"], c["key"])
            for c in cells.values()
            if c["observed"] is None
            or (c["observed"] and (c["astra"] not in judged or c["tdn"] not in judged))
        ]
        if pending:
            raise ValueError(
                f"{len(pending)} cells still require evidence or adjudication"
            )
        expected_reviews = {(n,k) for n in NETWORKS for k in [*controls,*(c.key for c in cases)]}
        if revised and (alerts["reviewed_sessions"] != len(expected_reviews) or
                        {(r["network"],r["case"]) for r in reviews if r.get("complete")} != expected_reviews):
            raise ValueError("Every faulty and fault-free session needs a complete finding-by-finding review")
        if current:
            for n in NETWORKS:
                checks = load(root/"controls"/(n+"-frozen")/"verification.json")
                if not checks or any(v["status"] != "pass" for v in checks.values()):
                    raise ValueError(f"Missing passing primary control proofs for {n}")
                for k in controls[1:]:
                    if load(root/"measurements"/n/k/"tdn-control.json").get("status") not in {"accepted","false_alarm","incomplete"}:
                        raise ValueError(f"Missing TDN outcome for {n}/{k}")

    def link(file, title):
        url = quote(os.path.relpath(file, out.parent), safe="/.")
        return f'<a href="{url}">{esc(title)}</a>'

    def badge(v, method):
        status = {
            "detected": ("hit", "✓"),
            "missed": ("miss", "×"),
            "unexercised": ("wait", "–"),
        }.get(v, ("wait", "…"))
        return f'<span class="pill {status[0]}" title="{esc(method + " " + v)}">{method} {status[1]}</span>'

    def by(n):
        return [v for v in cells.values() if v["net"] == n and v["observed"]]

    def score(rows, method):
        return sum(v[method] == "detected" for v in rows)

    def rate(rows, method):
        finished = [v for v in rows if v[method] in judged]
        return f"{score(finished, method)}/{len(finished)}" if finished else "—"

    def dist(values):
        if not values:
            return "—"
        return f"{seconds(median(values))} ({seconds(min(values))} to {seconds(max(values))})"

    observed = [v for v in cells.values() if v["observed"]]
    parts = [
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>TDN · Detecting single faults as networks grow</title><style>"
        + CSS
        + '</style><body><div class="shell">',
        '<nav aria-label="Contents">'
        + "".join(
            f'<a href="#{a}">{b}</a>'
            for a, b in [
                ("summary", "Results"),
                ("networks", "Three topologies"),
                ("scores", "20 fault types"),
                ("alerts", "False alerts"),
                ("misses", "Astra’s misses"),
                ("times", "Time"),
                ("cases", "Faults and evidence"),
                ("method", "Study design"),
            ]
        )
        + "</nav><main>",
        '<header id="summary"><p class="kicker">TDN · Snapshot experiment</p><h1>Can Astra still find the same fault in a larger network?</h1>',
    ]
    lead = f"Across {len(observed)} observed network faults, Astra identified {rate(observed, 'astra')} and TDN rejected {rate(observed, 'tdn')}."
    parts += [
        '<p class="lead">'
        + esc(lead)
        + '</p><p>Each faulty capture exercises one registered violation. Astra reads the CSfC document and one saved network. TDN checks the same network using Lean.</p><div class="cards">'
    ]
    for n in NETWORKS:
        rows = by(n)
        pieces = []
        for label, key in [("Astra", "astra"), ("TDN", "tdn")]:
            done = [r for r in rows if r[key] in judged]
            width = 100 * score(done, key) / len(done) if done else 0
            pieces.append(
                f'<div class="bar {key}"><b>{label}</b><div class="track"><div class="fill" style="width:{width:.1f}%"></div></div><strong>{rate(rows, key)}</strong></div>'
            )
        parts.append(
            f'<div class="card"><h3>{esc(n)}</h3>' + "".join(pieces) + "</div>"
        )
    parts.append('</div>')
    followup = out.parent/"naive-agent-method-revision.html"
    if root.name == "topology-scaling-20261125" and followup.is_file():
        parts.append('<p class="evidence">November 26 follow-up · ' +
                     link(followup, "Repaired TDN checks, revised sampling and Astra’s false alarms") +
                     '. The results below preserve the original run.</p>')
    parts.append('</header>')
    parts.append('<section id="alerts"><h2>How often did Astra raise a false alarm?</h2>')
    if alerts["reviewed_sessions"]:
        f = alerts["findings"]
        parts.append(f'<p>Reviewers checked {alerts["reviewed_sessions"]} complete answers. '
                     f'{f["false_positive"]} findings were contradicted by the evidence or the document. '
                     f'{f["other_real"]} described other genuine conditions. {f["unresolved"]} remained uncertain. '
                     f'{f["consequence"]} described additional effects of the planted fault.</p>')
        if alerts["reviewed_clean"]:
            parts.append(f'<p>{alerts["clean_with_false_alarm"]} of {alerts["reviewed_clean"]} separately audited '
                         f'healthy controls drew at least one confirmed false alarm. '
                         f'{alerts["clean_with_any_alert"]} drew an alert of any kind.</p>')
            if current:
                low,high = wilson_interval(alerts["clean_with_false_alarm"],alerts["reviewed_clean"])
                parts.append(f'<p>A 95% Wilson interval for the fraction of healthy sessions with a confirmed false alarm is '
                             f'{low:.1%} to {high:.1%} under an independent-trial assumption. The controls share three topologies.</p>')
                for k in controls:
                    group = alert_statistics([r for r in reviews if r["case"] == k])
                    parts.append(f'<p>{esc(k)}: {group["clean_with_false_alarm"]} of {group["reviewed_clean"]} audits raised a confirmed false alarm.</p>')
        else:
            parts.append('<p>No independently reviewed healthy-control answer is available to estimate a clean-network false-alarm rate.</p>')
        for review in reviews:
            for finding in review.get("findings", []):
                if finding["classification"] in {"false_positive","unresolved"}:
                    parts.append(f'<details><summary>{esc(review["network"])} · {esc(finding["classification"])}</summary>'
                                 f'<blockquote>{esc(finding["quotation"])}</blockquote><p>{esc(finding["reason"])} '
                                 f'{esc(finding["evidence"])}</p></details>')
    else:
        parts.append('<p>Individual alerts were not adjudicated in this run. Its false-alarm rate is unknown.</p>')
    if current:
        control_status = [load(root/"measurements"/n/k/"tdn-control.json").get("status") for n in NETWORKS for k in controls[1:]]
        comparison = ("Each fault uses its preregistered healthy configuration for scoring." if matched_variants else
                      "The three primary controls establish the baseline for scoring faults.")
        parts.append(f'<p>On the six additional healthy captures, Lean rejected {control_status.count("false_alarm")}, '
                     f'accepted {control_status.count("accepted")} and returned {control_status.count("incomplete")} incomplete results. '
                     f'{control_status.count(None)} have no recorded outcome. {comparison}</p>')
    parts.append('</section>')
    parts.append(
        '<section id="networks"><h2>Three networks change the size of the search</h2><div class="scroll"><table><thead><tr><th>Network</th><th>Levels</th><th>Devices</th><th>Links</th><th>Structure at each site</th></tr></thead><tbody>'
    )
    for n, desc in zip(
        NETWORKS,
        [
            "One Gray router and firewall connect two Gray switches to one Outer gateway and firewall.",
            "Twenty Red enclaves share one Gray router, Gray Firewall, Outer gateway and Outer Firewall.",
            "Ten copies of the two-level branch share one Black transport.",
        ],
    ):
        size = inventory(n)
        parts.append(
            f"<tr><th>{esc(n)}</th><td>{len(size['levels'])}</td><td>{size['devices']}</td><td>{size['links']}</td><td>{esc(desc)}</td></tr>"
        )
    parts += [
        '</tbody></table></div><p class="fine">Device counts include the administrative workstations and management switches. Twinet control processes and temporary measurement endpoints are excluded. The device-heavy network has 9.73 times as many devices as Base.</p></section>',
        '<section id="scores"><h2>Which faults did each method catch?</h2><p>Each cell gives Astra’s result first and TDN’s second. A check mark means detected. A cross means missed. A dash means the attempted change did not produce the intended violation.</p><div class="scroll"><table><thead><tr><th>Observed fault</th>'
        + "".join("<th>" + n + "</th>" for n in NETWORKS)
        + "</tr></thead><tbody>",
    ]
    for c in cases:
        values = [cells[c.key, n] for n in NETWORKS]
        parts.append(
            '<tr><td><a href="#'
            + c.key
            + '">'
            + esc(c.title)
            + "</a></td>"
            + "".join(
                '<td class="pair">'
                + badge(
                    v["astra"] if v["observed"] is not False else "unexercised", "A"
                )
                + " "
                + badge(v["tdn"] if v["observed"] is not False else "unexercised", "T")
                + "</td>"
                for v in values
            )
            + "</tr>"
        )
    all_three = [c for c in cases if all(cells[c.key, n]["observed"] for n in NETWORKS)]
    score3 = {
        m: sum(
            all(cells[c.key, n][m] == "detected" for n in NETWORKS) for c in all_three
        )
        for m in ("astra", "tdn")
    }
    parts += [
        "</tbody></table></div><p><b>Detection on all three networks.</b> Of "
        + str(len(all_three))
        + " types exercised on every network, Astra identified "
        + str(score3["astra"])
        + " on all three and TDN rejected "
        + str(score3["tdn"])
        + " on all three.</p></section>",
        '<section id="misses"><h2>What Astra missed</h2>',
    ]
    for n in NETWORKS:
        missed = [v for v in by(n) if v["astra"] == "missed"]
        parts.append(f"<h3>{n} · {len(missed)} missed</h3>")
        if not missed:
            parts.append(
                "<p>Every reviewed violation was identified.</p>"
                if all(v["astra"] in judged for v in by(n)) and by(n)
                else "<p>Review is in progress.</p>"
            )
        for v in missed:
            c = next(c for c in cases if c.key == v["key"])
            base = root / "measurements" / n / c.key
            agent = root / "trials" / c.key / n / "astra"
            parts.append(f"<article><b>{esc(c.title)}</b><p>{esc(v['reason'])}</p>")
            if v["quote"]:
                parts.append('<p class="quote">' + esc(v["quote"]) + "</p>")
            parts.append(
                '<p class="evidence">'
                + link(agent / "answer.md", "Astra’s full answer")
                + " · "
                + link(agent / "access.jsonl", "Snapshot queries")
                + " · "
                + link(Path(v["observation"]).parent if v["observation"] else base / "operator", "Observed change and restoration")
                + "</p></article>"
            )
    parts += [
        '</section><section id="times"><h2>Time to inspect and check one snapshot</h2><p>Values give the median and the shortest and longest run. Astra’s clock covers its entire session. TDN’s clock sums the Lean proof checks after their evidence has loaded.</p><div class="scroll"><table><thead><tr><th>Network</th><th>Astra wall time</th><th>TDN typecheck time</th><th>Astra reader calls, median</th></tr></thead><tbody>'
    ]
    for n in NETWORKS:
        rows = by(n)
        av = [r["astra_seconds"] for r in rows if r["astra_seconds"] is not None]
        lv = [
            r["tdn_seconds"]
            for r in rows
            if r["tdn_seconds"] is not None and r["timed_files"] == r["total_files"]
        ]
        calls = [r["queries"] for r in rows if r["queries"] is not None]
        parts.append(
            f"<tr><th>{n}</th><td>{dist(av)} · {len(av)} runs</td><td>{dist(lv)} · {len(lv)} complete timings</td><td>{median(calls) if calls else '—'}</td></tr>"
        )
    parts += [
        '</tbody></table></div><p class="fine">The one-hour limit applies to each Astra audit. Lean has twenty minutes per file. A partial Lean timing is recorded in the case log when another check fails to load evidence.</p></section>',
        '<section id="cases"><h2>What each change does</h2>',
    ]
    if current:
        coverage = clause_coverage(cases)
        exercised = {k for k,keys in coverage.items() if any(all(cells[key,n]["observed"] for n in NETWORKS) for key in keys)}
        parts.append(f'<p>The design targets {sum(bool(v) for v in coverage.values())} of {len(coverage)} distinct clauses. '
                     f'Independent observations exercise {len(exercised)} clauses on all three networks. A clause can have several duties.</p>')
    for c in cases:
        description = c.observation if revised else CHANGES[c.key] + " " + c.observation
        parts.append(f'<details id="{esc(c.key)}"><summary>{esc(c.title)}</summary><p><strong>{esc(c.rule)} · {esc(c.clause)}</strong></p><p>{esc(description)}</p>')
        for n in NETWORKS:
            v = cells[c.key, n]
            base = root / "measurements" / n / c.key
            parts.append(
                "<p><b>"
                + esc(n)
                + "</b> "
                + (esc(" · ".join(str(x) for x in (v["anchor"], v["level"]) if x)) + " " if revised else "")
                + esc(v["tdn_reason"])
                + " "
                + link(Path(v["observation"]).parent if v["observation"] else base / "operator", "Before, changed and restored readings")
                + " · "
                + link(base / "tdn/verification.json", "Lean results")
                + (" · " + link(control_run_root(root, n, v["control_variant"]) / "controls" /
                                (n + "-frozen") / "verification.json", "Matched control " + v["control_variant"])
                   if matched_variants and v["control_variant"] else "")
                + " · "
                + link(
                    root / "trials" / c.key / n / "astra/answer.md", "Astra’s answer"
                )
                + "</p>"
            )
        parts.append("</details>")
    if current:
        method_description = "<p>The study mixes sixty faulty captures with nine independently captured healthy controls. Every recorded firewall chain keeps its healthy first rule. Each topology has three healthy configurations with the same intended forwarding behavior.</p>"
        if matched_variants:
            method_description += "<p>Each topology assigns seven, seven and six fault types across its three healthy configurations. Each fault type uses the same variant on all three topologies. The audit copy also omits IPsec byte and packet counts.</p>"
    elif revised:
        method_description = "<p>The supervisor registers the device and security level before scoring. The qualification program compares row 1 of every captured IPv4 and IPv6 filter chain against the healthy control. The session order mixes faulty captures with three controls.</p>"
    else:
        method_description = "<p>Each network starts with passing TDN checks and successful delivery between its intended Red endpoints. The operator confirms one change, captures the converged network and restores service. Each cell gets a fresh Astra session and fresh Lean checks.</p>"
    parts += [
        '</section><section id="method"><h2>What the comparison measures</h2>',
        method_description,
        ("<p>Astra reads the PDF, the device roles and effective levels, the deployment policy, and recorded device output. The audit copy omits collector timestamps, IPsec session ages and firewall traffic counters. TDN imports the underlying capture with the declared design. The supervisor retains the original evidence and confirmation records.</p>" if current else
         "<p>Astra uses the local Python server <code>snapshot_reader.py</code> to read the PDF, list the declared devices and links, and search the saved observations. The server presents one snapshot under the name “network.” Both methods receive the intended design, effective classifications, gateway settings, kernel state and interface observations. The supervisor retains the fault names and independent confirmation records. Astra earns credit for a correct diagnosis even when Astra cites a different CSfC requirement.</p>"),
        ("<p>Astra earns credit for identifying the actual fault on the affected device. An alternative document citation is acceptable. TDN earns credit for a failed proof on imported data when the same proof program passes its healthy control. Incomplete imports are reported separately.</p>"
         if revised else "<p>The historical grader credited a substantiated fault or its effect. Lean credit required a related assertion to fail.</p>"),
        "<p>The twenty matched faults permit comparisons within each fault type. The twenty-level network also has more interfaces, routes and rules. A single Astra session per case leaves run-to-run variation in the results.</p>",
        ("" if current else "<p>The replacement for the blocked Outer-selector trial was MSC-PF-23. The replacement denies IKE between two authorized same-level Inner gateways at the Gray Firewall. In the discarded trial, an independent firewall still stopped a packet after the Outer selector changed.</p>"),
        '<p class="evidence">'
        + link(root / "protocol.json", "Frozen protocol")
        + " · "
        + link(root / "controls", "Clean checks")
        + " · "
        + link(root / "measurements", "All measurements")
        + "</p></section>",
        "<footer>CSfC Multi-Site Connectivity 1.3.0. All traffic and devices belong to isolated research emulations.</footer></main></div></body></html>",
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(parts))
    if not preview:
        (root / "scores.json").write_text(
            json.dumps(
                {"cells": list(cells.values()), "all_three": score3, "alerts": alerts},
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
        )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("results", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--preview", action="store_true")
    a = p.parse_args()
    build(a.results, a.output, a.preview)
