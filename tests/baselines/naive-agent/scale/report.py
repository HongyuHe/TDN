"""Render the independently reviewed 20-by-3 study and link each conclusion to its evidence."""

import argparse
import html
import json
import os
from pathlib import Path
from statistics import median
import sys
from urllib.parse import quote

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
from scale.catalog import CASES, CHANGES
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
        "tdn_reason": tdn.get("explanation", ""),
        "rejected": [k for k, v in checks.items() if v["status"] == "rejected"],
        "diagnostics": {
            k: v["status"]
            for k, v in checks.items()
            if v["status"] not in {"pass", "rejected"}
        },
    }


CSS = """
:root{color-scheme:light;--ink:#182b3c;--muted:#465d6c;--line:#cbd8de;--paper:#fff;--bg:#f4f7f7;--astra:#48468b;--tdn:#006553}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:20px}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}.shell{max-width:1350px;margin:auto;padding:32px;display:grid;grid-template-columns:170px minmax(0,1fr);gap:30px}nav{align-self:start;position:sticky;top:20px;border-left:2px solid var(--line);padding-left:15px}nav a{display:block;margin:9px 0;color:var(--ink);font-size:14px}main{min-width:0}a{color:#075d77;text-underline-offset:3px}h1,h2,h3,p{margin:0 0 .7em}h1{font-size:clamp(32px,4.1vw,54px);line-height:1.04;letter-spacing:-.048em;max-width:21ch}h2{font-size:27px;line-height:1.15;letter-spacing:-.025em}h3{font-size:18px}header,section{padding:27px 30px;background:var(--paper);border:1px solid var(--line);border-radius:13px;margin-bottom:20px}.kicker{color:#096953;font-size:13px;font-weight:700;letter-spacing:.045em;text-transform:uppercase}.lead{font-size:19px;max-width:66ch;color:#304a59}.fine,.evidence{font-size:14px;color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.card{border:1px solid var(--line);padding:14px;border-radius:8px}.large{font-size:31px;font-weight:720;letter-spacing:-.04em}.bar{display:grid;grid-template-columns:6ch minmax(0,1fr) 6ch;gap:7px;font-size:13px;margin:7px 0;align-items:center}.track{background:#e5ebeb;border-radius:6px;height:9px}.fill{height:100%;background:var(--astra);border-radius:inherit}.tdn .fill{background:var(--tdn)}.tag{font-size:12px;font-weight:650}.yes{color:#005947}.no{color:#a03838}.pending{color:#596b74}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:9px 7px;border-bottom:1px solid var(--line);vertical-align:top}th{font-weight:650;background:#f3f6f7}.code{font:12px ui-monospace,monospace;color:#485d6b}details{border-top:1px solid var(--line);padding:11px 0}summary{cursor:pointer;font-weight:620}.quote{border-left:3px solid #b6b5d7;padding-left:13px;color:#34495d}.pair{white-space:nowrap}.pill{padding:3px 6px;border-radius:4px;font-size:12px;font-weight:680}.hit{color:#005947;background:#e1f3eb}.miss{color:#922c36;background:#f9e7e8}.wait{color:#4a5b63;background:#edf1f1}footer{font-size:13px;color:var(--muted)}@media(max-width:950px){.shell{grid-template-columns:1fr;padding:12px;gap:12px}nav{z-index:2;top:0;background:#fafcfc;border:1px solid var(--line);border-radius:7px;padding:6px 10px;display:flex;gap:15px;overflow:auto}nav a{white-space:nowrap;margin:3px 0}.cards{grid-template-columns:1fr}section,header{padding:20px}.scroll{max-width:100%}}@media print{nav{display:none}.shell{display:block}section,header{break-inside:avoid;border:none}}
"""


def build(root, out, preview=False):
    root = root.resolve()
    out = out.resolve()
    cells = {(c.key, n): read_cell(root, n, c) for c in CASES for n in NETWORKS}
    judged = {"detected", "missed"}
    if not preview:
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
        + '</p><p>Each run changes one network setting. Astra reads the CSfC document and one saved network. TDN checks the same network using Lean.</p><div class="cards">'
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
    parts.append(
        '</div></header><section id="networks"><h2>Three networks change the size of the search</h2><div class="scroll"><table><thead><tr><th>Network</th><th>Levels</th><th>Devices</th><th>Links</th><th>Structure at each site</th></tr></thead><tbody>'
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
    for c in CASES:
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
    all_three = [c for c in CASES if all(cells[c.key, n]["observed"] for n in NETWORKS)]
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
            c = next(c for c in CASES if c.key == v["key"])
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
                + link(base / "operator", "Observed change and restoration")
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
    for c in CASES:
        parts.append(
            f'<details id="{esc(c.key)}"><summary>{esc(c.title)}</summary><p><strong>{esc(c.rule)} · {esc(c.clause)}</strong></p><p>{esc(CHANGES[c.key])}</p><p>{esc(c.observation)}</p>'
        )
        for n in NETWORKS:
            v = cells[c.key, n]
            base = root / "measurements" / n / c.key
            parts.append(
                "<p><b>"
                + esc(n)
                + "</b> "
                + esc(v["tdn_reason"])
                + " "
                + link(base / "operator", "Before, changed and restored readings")
                + " · "
                + link(base / "tdn/verification.json", "Lean results")
                + " · "
                + link(
                    root / "trials" / c.key / n / "astra/answer.md", "Astra’s answer"
                )
                + "</p>"
            )
        parts.append("</details>")
    parts += [
        '</section><section id="method"><h2>What the comparison measures</h2>',
        "<p>Each network starts with passing TDN checks and successful delivery between its intended Red endpoints. The operator changes one setting, independently observes the effect, captures the network after its routes and filters stabilize, and restores service. Each cell gets a fresh Astra session and fresh Lean checks.</p>",
        "<p>Astra has three read-only operations. It can read the PDF, list the captured devices and links, and search the saved records. It sees one network under the name “network.” Both methods receive the intended design, effective classifications, gateway settings, kernel state and interface observations. The operator’s fault name and verification probes are retained separately. Different CSfC citations receive credit when the detector identifies the actual problem.</p>",
        "<p>A failure to compile or import evidence earns no detection credit by itself. A reviewer checks whether a failed Lean obligation reflects the specific change. The controls and the frozen answer make each decision reproducible.</p>",
        "<p>Each topology was deployed once. The twenty matched faults permit comparisons within each fault type. The level-heavy network also has more interfaces, routes and rules. The study measures the combined effect of those changes. A single Astra session per cell leaves ordinary run-to-run variation in its results.</p>",
        "<p>The replacement for the blocked Outer-selector trial was MSC-PF-23. The replacement denies IKE between two authorized same-level Inner gateways at the Gray Firewall. In the discarded trial, an independent firewall still stopped a packet after the Outer selector changed.</p>",
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
                {"cells": list(cells.values()), "all_three": score3},
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
