"""Render the live benchmark's evidence, four-network rule, timings, and clause coverage."""

import argparse
from collections import Counter
from datetime import datetime, timedelta
import html
import json
import math
from pathlib import Path
from statistics import median
from urllib.parse import quote

from observe_controls import HERE
from score_trials import METHODS, type_verdict as active_verdict
import subprocess
NETWORKS = ("net-02", "net-03", "net-04", "net-05")
CREDITED = ("hit", "assigned_credit")
PAIRED_SOURCE = HERE / "runs/20261122-rg-clauses-01"
SNAPSHOT_RUN = HERE / "runs/20261123-rg-snapshots-01"


def type_verdict(values):
    if len(values) == len(NETWORKS) and all(v in CREDITED for v in values):
        return "hit"
    return active_verdict(values)


def historical_json(name):
    data = subprocess.check_output(["git", "show", "1d6e508c6f0665dcc282d8c8df84005912c05f0f:tests/baselines/naive-agent/" + name], cwd=HERE)
    return json.loads(data)

from snapshot_report import paired_report

ROOT = HERE.parents[2]
NAME = {"astra": "Astra High", "sol": "Sol High", "tdn": "TDN v3.4"}
COLORS = {"astra": "#7549a5", "sol": "#a15a15", "tdn": "#137481"}
PROFILES = {
    "net-02": "Two separate Red networks share one security level.",
    "net-03": "Four levels share the Outer gateways.",
    "net-04": "Four levels have redundant Outer gateways.",
    "net-05": "Two levels have dedicated management networks.",
}


def esc(x):
    return html.escape(str(x), quote=True)


def link(path, label, line=None):
    uri = (
        "vscode://file" + quote(str(path.resolve())) + (":" + str(line) if line else "")
    )
    return f'<a href="{esc(uri)}">{esc(label)}</a>'


def seconds(n):
    if n is None:
        return "pending"
    return f"{n:.3f} s" if n < 1 else (f"{n:.2f} s" if n < 60 else f"{n / 60:.1f} min")


def method_time(method, data):
    if method == "tdn" and data["seconds"] is None and data.get("proof_seconds"):
        return (
            seconds(data["partial_seconds"])
            + " across "
            + str(len(data["proof_seconds"]))
            + " completed modules"
        )
    if method == "tdn" and data["seconds"] is None:
        return "No complete proof interval"
    return seconds(data["seconds"])


def violation_catalog(rows, types, descriptions, clause_pointers):
    cards = []
    trial_descriptions = {}
    for family in sorted(types, key=lambda name: (types[name]["clause_ids"], name)):
        trials = [row for row in rows if row["type"] == family]
        if not trials:
            continue
        guide = descriptions[family]
        variants = []
        for variant in guide["variants"]:
            cases = [row for row in trials if row["network"] in variant.get("networks", NETWORKS)]
            if not cases:
                continue
            trial_links = []
            for row in cases:
                key = (family, row["network"])
                if key in trial_descriptions:
                    raise ValueError(f"Two descriptions match trial {key}")
                trial_descriptions[key] = variant
                trial_links.append(
                    f'<a href="#trial-{esc(family)}-{esc(row["network"])}">'
                    f'{esc(row["network"])} <code>{esc(row["target"])}</code></a>'
                )
            profile_heading = ""
            if len(guide["variants"]) > 1:
                profile_heading = "<h4>" + " and ".join(esc(row["network"]) for row in cases) + "</h4>"
            variants.append(
                f'{profile_heading}<dl class="fault-facts"><dt>Requirement</dt><dd>{esc(variant["requirement"])}</dd>'
                f'<dt>Injected change</dt><dd>{esc(variant["change"])}</dd>'
                f'<dt>Trial evidence</dt><dd class="trial-links">{"".join(trial_links)}</dd></dl>'
            )
        clauses = ", ".join(clause_pointers[cid] for cid in types[family]["clause_ids"])
        note = f'<p class="sidenote">{esc(guide["note"])}</p>' if guide.get("note") else ""
        cards.append(
            f'<article class="fault-card" id="fault-{esc(family)}"><div>{clauses}</div>'
            f'<h3>{esc(types[family]["title"])}</h3>{"".join(variants)}{note}</article>'
        )
    if len(trial_descriptions) != len(rows):
        raise ValueError("Every scored trial must have one violation description")
    return "".join(cards), trial_descriptions


def trial_change_field(folder, row):
    change = json.loads((folder / "change.json").read_text())
    target, network = row["target"], row["network"]
    if "ports" in change:
        before = json.loads((folder / "before.json").read_text())
        endpoints = {(target, port) for port in change["ports"]}
        links = []
        for link_row in before["links"]:
            pair = [(link_row[k]["device"], link_row[k]["interface"]) for k in ("a", "b")]
            if endpoints.intersection(pair):
                links.append(" ↔ ".join(f"{device}.{iface}" for device, iface in pair))
        label, values = "Disconnected links", links
    elif "original_address" in change:
        label = "Running peer, before and after"
        values = [f'{change["original_address"]} → {change["running_address"]}']
    elif row["type"] in ("inner-mode", "outer-mode"):
        before = json.loads((folder / "before.json").read_text())[network][target]
        snapshot = json.loads((folder / "snapshot.json").read_text())[network]
        after = next(device["mode"] for device in snapshot if device["device"] == target)
        label, values = "Loaded ESP mode, before and after", [f"{before} → {after}"]
    else:
        probes = json.loads((folder / "independent-evidence.json").read_text())["probe"]
        label = "Test traffic affected"
        values = [
            f'{p["source"]} → {p["destination"]}' for p in probes
            if p.get("delivered") is False or p.get("accepted_by_local_ip") is True
        ]
    if not values:
        raise ValueError(f"No recorded change detail for {folder}")
    items = "".join(f"<li><code>{esc(value)}</code></li>" for value in values)
    return f'<dt>{label}</dt><dd><ul class="case-values">{items}</ul></dd>'


def timings_on_same_trials(rows):
    complete = [
        row["methods"] for row in rows
        if all(
            item["seconds"] is not None and item["verdict"] in ("hit", "miss")
            for item in row["methods"].values()
        )
    ]
    if not complete:
        return ""
    medians = [seconds(median(row[m]["seconds"] for row in complete)) for m in METHODS]
    rechecked = sum("tdn_recheck" in row for row in rows)
    replay_note = (
        f" For the {rechecked} protocol-253 cases, the TDN times come from rerunning all eight "
        "checks on the saved snapshots. The Detector times come from the original live audits."
        if rechecked else ""
    )
    return (
        f"<p>All three methods completed their measured work on {len(complete)} of "
        f"{len(rows)} trials. For those same cases, median times were {medians[0]} "
        f"for GPT-6 Astra, {medians[1]} for GPT-6 Sol and {medians[2]} for the Lean "
        "checks. A trial with an interrupted import contributes its completed Lean "
        f"intervals to the individual record.{replay_note}</p>"
    )


def times_by_network(rows, root):
    if not (root / "delivery-protocol.json").is_file():
        return ""
    controls = json.loads((root / "delivery-protocol.json").read_text())
    table = []
    for n in NETWORKS:
        cells = []
        for method in METHODS:
            values = [
                r["methods"][method]["seconds"]
                for r in rows
                if r["network"] == n
                and r["methods"][method]["seconds"] is not None
                and r["methods"][method]["verdict"] in ("hit", "miss")
            ]
            cells.append(
                "<td>"
                + esc(seconds(median(values)))
                + f" <small>{len(values)} cases</small></td>"
                if values
                else "<td>Pending</td>"
            )
        table.append(
            f"<tr><th>{n}</th><td>{controls['allowed_pairs'][n]}</td><td>{controls['forwarding_steps'][n]}</td>"
            + "".join(cells)
            + "</tr>"
        )
    return (
        '<details><summary>Median time by network and size of its permitted paths</summary><div class="tablewrap"><table><thead><tr><th>Network</th><th>Red pairs</th><th>Path steps</th><th>Astra High</th><th>Sol High</th><th>TDN</th></tr></thead><tbody>'
        + "".join(table)
        + "</tbody></table></div><p>Each Detector sees all four networks. The network column names the one with the injected change. TDN checks that network’s snapshot.</p></details>"
    )


def elapsed_figure(root):
    trial = root / "trials/inner-mode/net-02"
    if not (trial / "adjudication.json").is_file():
        return ""
    events = [
        json.loads(line) for line in (trial / "events.jsonl").read_text().splitlines()
    ]
    start = datetime.fromisoformat(
        next(e["at"] for e in events if e["event"] == "single_fault_observed")
    )
    restored = datetime.fromisoformat(
        next(e["at"] for e in events if e["event"] == "restoration_verified")
    )

    def offset(d):
        return (d - start).total_seconds() / 60

    end = offset(restored)
    scale = 445 / max(end, 1)
    items = []
    snap = json.loads((root / "raw/trials/inner-mode/net-02/capture.json").read_text())
    for name, value, timefield, color in [
        ("Snapshot capture", snap, "seconds", "#377e91")
    ] + [
        (
            NAME[m],
            json.loads((trial / m / "execution.json").read_text()),
            "duration_seconds",
            COLORS[m],
        )
        for m in ("astra", "sol")
    ]:
        began = datetime.fromisoformat(value["started_at"])
        duration = value[timefield]
        items.append(
            (name, offset(began), offset(began + timedelta(seconds=duration)), color)
        )
    shapes = []
    for tick in range(0, math.ceil(end) + 1, 2):
        x = 139 + tick * scale
        shapes.extend(
            [
                f'<line x1="{x}" y1="10" x2="{x}" y2="104" stroke="#dce5e7"/>',
                svgtext(x, 124, f"{tick} min", 'text-anchor="middle"'),
            ]
        )
    for i, (name, left, right, color) in enumerate(items):
        y = 22 + 30 * i
        shapes.extend(
            [
                svgtext(4, y + 6, name),
                f'<rect x="{139 + scale * left}" y="{y - 5}" width="{max(1, scale * (right - left))}" height="13" rx="4" fill="{color}"/>',
            ]
        )
    stop = 139 + scale * end
    shapes.extend(
        [
            f'<line x1="{stop}" y1="7" x2="{stop}" y2="102" stroke="#45606a" stroke-dasharray="3 3"/>',
            svgtext(stop, 143, "Restored", 'text-anchor="middle"'),
        ]
    )
    return (
        '<figure><h3>One trial from fault to restoration</h3><svg class="chart" viewBox="0 0 635 152" role="img" aria-label="Overlapping capture and Detector runtimes for the net-02 Inner trial">'
        + "".join(shapes)
        + "</svg><figcaption>Minutes after the changed setting was confirmed on net-02. Capture and the two audits ran concurrently. Each Lean timing interval excludes snapshot loading.</figcaption></figure>"
    )


def label(status):
    return {
        "hit": "Found",
        "assigned_credit": "Assigned credit",
        "miss": "Missed",
        "timeout": "Time limit",
        "pending": "Pending",
        "unevaluable": "No valid result",
        "inapplicable": "Outside scope",
    }.get(status, status)


def tag(status, text=None):
    return f'<span class="tag {esc(status)}">{esc(text or label(status))}</span>'


def svgtext(x, y, value, more=""):
    return f'<text x="{x}" y="{y}" {more}>{esc(value)}</text>'


def coverage_table(scope, rows):
    observed = {(cid, r["network"]) for r in rows for cid in r["clauses"]}
    totals = Counter()
    entries = []
    bars = []
    palette = ("#246b68", "#dbab55", "#c4ced3", "#9b88b1")
    for group in dict.fromkeys(k.split(".")[0] for k in scope):
        counts = Counter()
        for cid, v in scope.items():
            if not cid.startswith(group + "."):
                continue
            for n, status in v["scope"].items():
                key = (
                    "exercised"
                    if (cid, n) in observed
                    else "open"
                    if status in ("applicable", "partly applicable")
                    else status
                )
                counts[key] += 1
        totals.update(counts)
        numbers = [
            counts[x]
            for x in ("exercised", "open", "inapplicable", "selection unconfirmed")
        ]
        y = 15 + len(entries) * 25
        bars.append(svgtext(0, y + 7, group))
        left = 82
        for number, color in zip(numbers, palette):
            width = 336 * number / sum(numbers)
            if width:
                bars.append(
                    f'<rect x="{left}" y="{y - 5}" width="{width}" height="14" fill="{color}"/>'
                )
            left += width
        bars.append(svgtext(432, y + 7, f"{numbers[0]}/{sum(numbers)} exercised"))
        entries.append(
            "<tr><th>"
            + group
            + "</th>"
            + "".join(f"<td>{v}</td>" for v in numbers)
            + "</tr>"
        )
    columns = [
        "Branch exercised",
        "Applicable, unexercised",
        "Inactive",
        "Selection unknown",
    ]
    table = (
        '<div class="tablewrap"><table><thead><tr><th>Requirement group</th>'
        + "".join("<th>" + v + "</th>" for v in columns)
        + "</tr></thead><tbody>"
        + "".join(entries)
        + "</tbody></table></div>"
    )
    legend = " ".join(
        f'<span style="margin-right:.85em"><i aria-hidden="true" style="display:inline-block;width:.75em;height:.75em;margin-right:.3em;background:{c}"></i>{esc(k)}</span>'
        for k, c in zip(columns, palette)
    )
    figure = (
        '<figure><svg class="chart" style="max-width:625px" viewBox="0 0 570 258" role="img" aria-label="Clause coverage by requirement group">'
        + "".join(bars)
        + "</svg><figcaption>"
        + legend
        + "</figcaption></figure>"
    )
    return (
        figure
        + "<details><summary>Counts for each group</summary>"
        + table
        + "</details>",
        totals,
    )


def inactive_table(scope):
    rows = []
    for cid, v in scope.items():
        networks = [n for n, s in v["scope"].items() if s == "inapplicable"]
        if networks:
            rows.append(
                "<tr><th>"
                + esc(cid)
                + "</th><td>"
                + esc(v["name"])
                + "</td><td>"
                + esc(", ".join(networks))
                + "</td><td>"
                + esc(v["scope_reason"])
                + "</td></tr>"
            )
    return (
        '<details><summary>Clauses with an inactive condition on at least one original network</summary><div class="tablewrap"><table><thead><tr><th>Clause</th><th>Duty</th><th>Profiles outside scope</th><th>Reason</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div></details>"
    )


def observed_duty(duty, rows):
    field = duty.get("requires_observation")
    return {
        r["network"]
        for r in rows
        if r["type"] in duty.get("types", [])
        and (field is None or r.get(field) is True)
    }


def duty_counts(scope, breakdown, rows):
    totals = Counter()
    for cid, record in scope.items():
        for duty in breakdown.get(cid, [{"duty": record["interpretation"]}]):
            totals["entries"] += 1
            measured = observed_duty(duty, rows)
            for n, state in record["scope"].items():
                if state == "inapplicable" or n not in duty.get("profiles", NETWORKS):
                    totals["inactive"] += 1
                elif state == "selection unconfirmed":
                    totals["undecided"] += 1
                else:
                    totals["active"] += 1
                    totals["observed"] += int(n in measured)
    return totals


def branch_details(cid, record, breakdown, rows):
    duties = breakdown.get(cid, [{"duty": record["interpretation"]}])
    result = []
    active = {
        n
        for n, s in record["scope"].items()
        if s in ("applicable", "partly applicable")
    }
    undecided = {n for n, s in record["scope"].items() if s == "selection unconfirmed"}
    for duty in duties:
        applies = active.intersection(duty.get("profiles", NETWORKS))
        measured = sorted(observed_duty(duty, rows))
        if not set(measured) <= applies:
            raise ValueError("A scored branch is outside its applicability: " + cid)
        context = (
            ("Active on " + ", ".join(sorted(applies)) + ".")
            if applies
            else (
                "Objective selection is unknown."
                if undecided
                else "The trigger is absent from the original networks."
            )
        )
        if measured:
            context += " Fault observed on " + ", ".join(measured) + "."
        elif applies:
            context += " No live violation has been measured for this duty."
        result.append(
            "<li>"
            + esc(duty["duty"])
            + " <small>"
            + esc(context + " " + duty.get("condition", ""))
            + "</small></li>"
        )
    return "<ul>" + "".join(result) + "</ul>"


def profile_figure(control):
    roles = [
        ("Inner gateways", {"inner"}, "#945b80"),
        ("Outer gateways", {"outer"}, "#497f9a"),
        ("Firewalls", {"firewall", "gray-firewall"}, "#c29351"),
        ("Other devices", set(), "#c6d1d4"),
    ]
    parts = []
    for i, network in enumerate(control["networks"]):
        y = 9 + i * 47
        parts.append(svgtext(7, y + 17, network["network"]))
        counts = Counter(d["role"] for d in network["devices"])
        x = 87
        accounted = 0
        for name, selected, color in roles:
            n = (
                sum(counts[r] for r in selected)
                if selected
                else len(network["devices"]) - accounted
            )
            width = n * 6
            accounted += n
            parts.append(
                f'<rect x="{x}" y="{y + 3}" width="{width}" height="17" fill="{color}"><title>{esc(name)}: {n}</title></rect>'
            )
            x += width
        parts.append(svgtext(x + 8, y + 17, str(accounted)))
        parts.append(svgtext(88, y + 36, PROFILES[network["network"]]))
    legend = " ".join(
        f'<span style="display:inline-flex;align-items:center;margin-right:.8em"><i aria-hidden="true" style="width:.75em;height:.75em;margin-right:.32em;background:{c}"></i>{esc(n)}</span>'
        for n, _, c in roles
    )
    return (
        '<figure><svg class="chart" style="max-width:580px" viewBox="0 0 540 193" role="img" aria-label="Devices and architecture of each original network">'
        + "".join(parts)
        + "</svg><figcaption>"
        + legend
        + "</figcaption></figure>"
    )


def control_notes(root):
    values = []
    credentials = root / "control-certificates.json"
    if credentials.is_file():
        values.append(
            "<p>The original deployments had expired certificates and revocation lists "
            "when testing began. Renewing them allowed the original gateway pairs to "
            "authenticate before the first scored change. Every trial used that working "
            "state as its control. "
            + link(credentials, "Certificate renewal and tunnel observations") + "</p>"
        )
    final = root / "final-health.json"
    if final.is_file():
        result = json.loads(final.read_text())
        if result["healthy"]:
            states = result["networks"]
            links = sum(s["healthy_links"] for s in states)
            ends = sum(len(s["tunnels"]["after"]) for s in states)
            paths = sum(len(s["delivery"]) for s in states)
            values.append(
                f"<p>The final live check found {links} links up and {ends} tunnel "
                f"endpoints with installed associations. All {paths} intended Red "
                "delivery directions worked again. Each gateway’s configured peer "
                "and ESP mode matched the original control. "
                + link(final, "Final observations on all four networks") + "</p>"
            )
    if (root / "controls/unclassified-placement.json").exists():
        values.append(
            "<p>Both four-level profiles already placed their Unclassified Inner and Outer gateways on one physical worker. RG-008 includes a physical-separation duty for an included Unclassified network. Reporting the existing placement earns no injected-fault credit. "
            + link(
                root / "controls/unclassified-placement.json", "Live placement record"
            )
            + "</p>"
        )
    if (root / "controls/net-05-approved-management.json").exists():
        values.append(
            "<p>On net-05, the authorized workstation could open a TCP connection to its Gray Firewall’s dedicated management interface. TLS certificate verification failed later because the management certificate had expired. A management packet-admission trial can establish whether TCP reached the service. "
            + link(
                root / "controls/net-05-approved-management.json", "Management control"
            )
            + "</p>"
        )
    return "".join(values)


def attempt_notes(root):
    items = []
    ssh_attempt = root / "attempts/ssh-command-too-long/firewall-inside-disconnected/net-02"
    if (ssh_attempt / "no-change-observed.json").is_file():
        items.append(
            "<p>SSH rejected the first inside-link command on net-02 before the worker "
            "received it. All 20 links and four intended deliveries still worked. "
            "The retry sent the worker over standard input. The unused attempt has no "
            "Detector or Lean score. " + link(ssh_attempt / "no-change-observed.json", "Live checks")
            + "</p>"
        )
    peer_attempt = root / "attempts/read-only-swanctl-directory/inner-peer-loopback/net-02"
    if (peer_attempt / "no-change-observed.json").is_file():
        items.append(
            "<p>The first peer-change attempt encountered the gateway’s read-only configuration "
            "directory. Both the running peer and the original file retained their previous "
            "values. The corrected loader used a temporary directory and the existing public "
            "certificates. Loading the original connection through that same loader preserved "
            "its settings. The excluded attempt ended before either Detector started. "
            + link(peer_attempt / "no-change-observed.json", "Original peer and delivery checks")
            + "</p>"
        )
    initial = root / "attempts/unsettled-state/inner-mode/net-04"
    if initial.exists():
        items.append(
            "<p>The first net-04 Inner-mode run changed one connection setting as intended, but a different gateway’s IPsec policy changed during snapshot collection. The complete trial was repeated with fresh Detectors. Astra found the mode change on both attempts. Sol reported only management issues on the excluded attempt and found the mode change on the repeat. Both answers remain available. "
            + link(initial / "reason.txt", "Exclusion reason")
            + " "
            + link(initial / "trial/sol/answer.md", "First Sol response")
            + " "
            + link(
                root / "trials/inner-mode/net-04/sol/answer.md", "Scored Sol response"
            )
            + "</p>"
        )
    amendment = root / "amendments/01-gray-firewall-condition/reason.json"
    if amendment.exists():
        items.append(
            "<p>PF-23 makes a Gray Firewall mandatory when several protection levels share the solution. The corrected placement check follows the optional branch on net-02. The same saved snapshots were checked again, with both versions and their evidence preserved. "
            + link(amendment, "Source and recheck record")
            + "</p>"
        )
    if (root / "delivery-protocol.json").exists():
        items.append(
            "<p>The permitted-delivery check was added before the first forwarding-denial trial. It was then applied to the saved earlier mode trials. The machine-readable scores retain both the six original proof times and the time for the expanded suite. "
            + link(root / "delivery-protocol.json", "Delivery check registration")
            + "</p>"
        )
    outside = root / "amendments/03-firewall-outside-attachment/registration.json"
    if outside.is_file():
        items.append(
            "<p>The inside and outside links are separate duties in RG-034.02. The outside-link experiment was added before any trial on that side. Its restoration check also verifies the original OSPF destinations, next hops and metrics. "
            + link(outside, "Outside-link test and controls")
            + "</p>"
        )
    gray = root / "gray-connectivity-protocol.json"
    if gray.is_file():
        items.append(
            "<p>The Gray Firewall connection check was added before its first disconnection trial. All four original controls passed. The check also runs on the earlier saved live captures. The timing data preserve the six-check, seven-check and complete totals. "
            + link(gray, "Gray path checks and reference hashes")
            + "</p>"
        )
    return (
        "<details><summary>Repeated trials and changes to the experimental procedure</summary>"
        + "".join(items)
        + "</details>"
        if items
        else ""
    )


def proof_panel(root):
    applications = historical_json("proof_applications.json")
    rows = []
    for rg, item in applications.items():
        source = link(HERE / item["check"], item["check"]) if item["check"] else ""
        rows.append(
            f"<tr><th>{rg}</th><td>{esc(item['meaning'])} {source}</td><td>{esc(item['scope'])}</td></tr>"
        )
    path_note = ""
    if (root / "delivery-protocol.json").exists():
        registration = json.loads((root / "delivery-protocol.json").read_text())
        pairs = sum(registration["allowed_pairs"].values())
        steps = sum(registration["forwarding_steps"].values())
        path_note = (
            f"<p>The four clean captures supply {pairs} intended deliveries with {steps:,} route, filter, encryption, decryption and delivery steps. TDN rechecks the very same permitted journeys against each affected snapshot. Each step uses the existing forwarding semantics. "
            + link(
                ROOT / "TDN/Models/RecordedForwarding.lean",
                "Forwarding step checker",
                85,
            )
            + " "
            + link(root / "delivery-protocol.json", "Clean paths and source hashes")
            + "</p>"
        )
    return (
        '<section id="proofs"><h2>What TDN typechecks on a fresh capture</h2>'
        + path_note
        + "<p>The mode trials change the setting that strongSwan has loaded for its next negotiation. The benchmark checks those strings directly. The original deployment proof also checks the installed association and the matching policy. The benchmark proves a connection to the full requirement under an explicit assumption that the loaded mode represents the component configuration. A gateway can still have a working association that negotiated the original mode. "
        + link(HERE / "ModeChecks.lean", "ModeObservationsMatch", 14)
        + " "
        + link(
            ROOT / "TDN/Deployments/InnerTunnelNoBypass_IpsecTunnelBindings.lean",
            "Original installed-tunnel check",
            25,
        )
        + "</p>"
        + "<p>The Gray connection check matches both endpoints of every observed virtual link. A working Gray Firewall has a checked path from an Inner and a checked path to an Outer. If a firewall loses contact with every Inner, Lean can also check the entire set of devices still connected to it and verify that the set contains no Inner. "
        + link(
            HERE / "GrayConnectivityChecks.lean", "Gray paths and disconnected devices"
        )
        + "</p>"
        + '<p>The project has ten reviewed model proofs. Each fresh deployment supplies facts for the following proof applications. The coverage column identifies the particular parts exercised in each trial.</p><div class="tablewrap"><table><thead><tr><th>Group</th><th>Proof and observation</th><th>Coverage</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div></section>"
    )


def header_recheck_report(rows, root):
    cases = [row for row in rows if "tdn_recheck" in row]
    if not cases:
        return ""
    record = root / cases[0]["tdn_recheck"]
    details = json.loads(record.read_text())
    lines = []
    for case in cases:
        name = case["network"]
        run = details["networks"][name]
        clean = record.parent / "controls" / name / "tdn-full/headers/result.json"
        fault = record.parent / "trials" / name / "tdn-full/headers/result.json"
        diagnostic = (root / case["record"]).parent / "tdn-full/translation-diagnostic.json"
        lines.append(
            f'<tr><th scope="row">{esc(name)}</th><td>{link(clean, run["controls"]["checks"]["headers"].capitalize())}</td>'
            f'<td>{link(fault, run["trials"]["checks"]["headers"].capitalize())}</td>'
            f'<td>{seconds(run["trials"]["typecheck_ns"] / 1e9)}</td><td>{link(diagnostic, "Original import error")}</td></tr>'
        )
    detections = sum(row["methods"]["tdn"]["verdict"] == "hit" for row in cases)
    return (
        '<div id="protocol-253-rerun"><h3>TDN checks the rule that admits protocol 253</h3>'
        '<p>The same rule appeared as <code>"253"</code> in the iptables listing and <code>253</code> in the nftables listing. '
        'The original importer treated those values as different and stopped. The repaired importer reads both as the same IP protocol. '
        'The rule then reaches Lean, which checks that every rule allowing traffic on a VPN gateway requires TCP, UDP, ESP or ICMP.</p>'
        f'<p>The clean header proof passed on all {len(cases)} networks. TDN detected the violation in {detections} of '
        f'{len(cases)} faulty snapshots. The rerun used the original Lean theory and proof programs. '
        'All eight checks on each clean control received the same inputs recorded in the original experiment.</p>'
        '<div class="tablewrap"><table><thead><tr><th>Network</th><th>Clean header proof</th><th>Faulty header proof</th>'
        '<th>All eight checks on faulty snapshot</th><th>Original evidence</th></tr></thead>'
        f'<tbody>{"".join(lines)}</tbody></table></div><p class="source">'
        f'{link(HERE / "HeaderCompliance.lean", "Lean protocol rule", 24)} &nbsp; {link(record, "Rerun records and snapshot hashes")} &nbsp; '
        f'{link(record.parent / "lean-dependencies.json", "Lean source and build hashes")}</p></div>'
    )


def takeaways(rows, root):
    sections = []
    repaired_headers = header_recheck_report(rows, root)
    if repaired_headers:
        sections.append(repaired_headers)
    outer = [r for r in rows if r["type"] == "outer-eligible-deny"]
    black = [r for r in rows if r["type"] == "delivery-outage"]
    if len(outer) == len(black) == len(NETWORKS) and all(
        r["methods"][m]["verdict"] == verdict
        for case_rows, verdict in ((outer, "hit"), (black, "miss"))
        for r in case_rows for m in ("astra", "sol")
    ):
        sections.append(
            "<p><b>The two models found every block on an Outer gateway and missed every "
            "block on a Black router.</b> Each Outer rule denied one intended pair of Inner "
            "gateways. The matching requirement names the Outer gateway and the traffic it "
            "must allow. A Black router’s rule interrupted every intended Red delivery on its "
            "network. Recognizing that violation required following the affected traffic across "
            "devices. On net-04 both models traced the installed route through the selected "
            "Outer gateway. The answers and device-query logs document where they looked.</p>"
        )
    unresolved_headers = []
    for row in rows:
        diagnostic = root / Path(row["record"]).parent / "tdn-full/translation-diagnostic.json"
        if row["type"] == "inner-empty-ipv4-header" and row["methods"]["tdn"]["verdict"] == "unevaluable" and diagnostic.is_file():
            details = json.loads(diagnostic.read_text())["mismatches"]
            if len(details) == 1 and details[0]["same_protocol_number_in_text_and_numeric_form"]:
                unresolved_headers.append((row["network"], diagnostic))
    if unresolved_headers:
        sections.append("<p><b>An import error can leave a real violation without a Lean verdict.</b> "
                        + esc(", ".join(n for n,_ in unresolved_headers))
                        + " admitted an empty IPv4 packet carrying protocol 253. The two firewall views both recorded 253. One supplied it as text and the other as a number. TDN compared them as different values and stopped before checking the header rule. Under the agreed scoring rule, those cases earn zero TDN detection credit. "
                        + link(unresolved_headers[0][1],"Values and original observation files") + "</p>")
    perimeter = next(
        (r for r in rows if r["type"] == "firewall-local-empty-udp" and r["network"] == "net-02"),
        None,
    )
    if perimeter and perimeter["methods"]["astra"]["verdict"] == perimeter["methods"]["tdn"]["verdict"] == "hit":
        folder = (root / perimeter["record"]).parent
        sections.append(
            "<p><b>A device shows which traffic it allows. The approval record says which "
            "traffic the owner authorized.</b> On net-02, Astra named the exact empty UDP "
            "datagram that the Outer Firewall accepted. It qualified its finding because "
            "the PDF allows approved control traffic. Astra earned credit for identifying "
            "the change. TDN also had the separate approval record, which lists OSPF, "
            "and its firewall check rejected the rule. "
            + link(folder / "astra/answer.md", "Astra’s answer", 6) + " "
            + link(HERE / "perimeter/approved-control-policy.json", "Recorded control policy")
            + "</p>"
        )
    overlooked = [
        r
        for r in rows
        if r["type"] in ("inner-mode", "outer-mode")
        and r["methods"]["sol"]["verdict"] == "miss"
        and r["methods"]["sol"]["observations"]["visible_target_settings"]
    ]
    if overlooked:
        samples = ", ".join(r["target"] + " on " + r["network"] for r in overlooked)
        sections.append(
            "<p><b>Sol received the changed setting and omitted it from its answer.</b> The reader responses contain the transport-mode setting for "
            + esc(samples)
            + ". The complete responses describe management issues. The case records preserve the observation logs and the submitted answers.</p>"
        )
    example = next(
        (r for r in rows if r["type"] == "inner-mode" and r["network"] == "net-02"),
        None,
    )
    if example:
        sections.append(
            "<p><b>An installed tunnel and the next tunnel negotiation can tell different stories.</b> The live association on net-02 still used tunnel mode. The Inner gateway had already loaded transport mode for its next negotiation. Astra identified the setting, Sol reported the management setup, and Lean rejected the loaded setting. "
            + link(
                HERE / "ModeChecks.lean", "Lean condition for the configured mode", 9
            )
            + "</p>"
        )
    outage = next(
        (
            row
            for row in rows
            if row["type"] == "delivery-outage" and row["network"] == "net-02"
        ),
        None,
    )
    if outage and outage["delivery_paths"]:
        paths = outage["delivery_paths"]
        stops = [step for pair in paths["pairs"] for step in pair["failed_steps"]]
        if stops and all(
            step["action"] == "filter"
            and step["iface"].startswith(outage["target"] + ":")
            for step in stops
        ):
            sections.append(
                f"<p><b>One rule cut off both Red networks on net-02.</b> Each intended delivery worked before the trial. All {paths['pairs_with_a_failed_step']} paths then failed at the Black router’s forwarding filter. The double-encryption check still passed. A Black router can discard a packet that arrived with both required layers. A separate proof required a working route to each intended peer. The new rule counted the probe packets, and restoring the original rules restored the deliveries. "
                + link(
                    root / Path(outage["record"]).parent / "path-diagnostics.json",
                    "Interfaces and failed steps",
                )
                + "</p>"
            )
    specific = next(
        (r for r in rows if r["type"] == "outer-eligible-deny" and r["network"] == "net-02"),
        None,
    )
    if specific and specific["delivery_paths"]:
        folder = (root / specific["record"]).parent
        probes = json.loads((folder / "independent-evidence.json").read_text())["probe"]
        failed = [p for p in specific["delivery_paths"]["pairs"] if p["failed_steps"]]
        stopped = sum(not p["delivered"] for p in probes)
        if len(failed) == 1 and stopped == 2:
            path = failed[0]
            sections.append(
                "<p><b>One blocked direction can make two pings fail.</b> A ping needs a request "
                "and a reply. On net-02 the first Red host at each site lost contact with its "
                "peer. The Lean checks follow each direction separately. Only the path from "
                + esc(path["source"]) + " to " + esc(path["destination"]) + " failed. "
                "The captured filter rejected that direction at "
                + esc(path["failed_steps"][0]["iface"]) + ". "
                + link(folder / "path-diagnostics.json", "Results for all four paths") + "</p>"
            )
    for t, title in [
        ("delivery-outage", "Blocking every delivery"),
        ("firewall-inside-disconnected", "Disconnecting a firewall"),
    ]:
        selected = [r for r in rows if r["type"] == t]
        if selected:
            count = sum(r["methods"]["tdn"]["verdict"] == "hit" for r in selected)
            sections.append(
                "<p><b>"
                + title
                + ".</b> Lean rejected "
                + str(count)
                + " of "
                + str(len(selected))
                + " verified changes of this type. The trial records show the independent delivery or attachment observation and the exact proof outcome.</p>"
            )
    disconnected = next(
        (r for r in rows if r["type"] == "firewall-inside-disconnected" and r["network"] == "net-02"),
        None,
    )
    if disconnected:
        proofs = disconnected["methods"]["tdn"]["proof_results"]
        if proofs.get("attachments") == "rejected" and proofs.get("topology") == "import_error":
            folder = (root / disconnected["record"]).parent
            sections.append(
                "<p><b>A missing interface can still supply evidence for a proof.</b> "
                "On net-02, repeated live interface lists agreed that the Outer Firewall "
                "had lost its inside connection. Lean could evaluate the required "
                "attachment directly from those lists and rejected it. A separate "
                "importer needed more observations from that firewall to build the whole "
                "forwarding model. Those other checks have no verdict. "
                + link(folder / "attachment-check/result.json", "Lean attachment result") + " "
                + link(folder / "interface-stability.json", "Repeated live observations") + "</p>"
            )
    outside = next(
        (r for r in rows if r["type"] == "firewall-outside-disconnected" and r["network"] == "net-04"),
        None,
    )
    if outside and outside["methods"]["sol"]["verdict"] == "miss":
        folder = (root / outside["record"]).parent
        sections.append(
            "<p><b>Seeing the outage can leave its cause open.</b> On net-04 Sol saw the "
            "primary tunnel down and the backup unused. Either the inside or outside firewall "
            "link could produce those observations. The trial had disconnected the outside "
            "link. Astra identified its two ends and received credit even though it cited "
            "the redundancy section. Sol’s case note records the outage it found. "
            "Its score for identifying the outside-link fault is a miss. "
            + link(folder / "sol/answer.md", "Sol’s finding", 8) + " "
            + link(folder / "astra/answer.md", "Astra’s interface observations", 17) + "</p>"
        )
    gray_trial = next(
        (r for r in rows if r["type"] == "gray-firewall-detached" and r["network"] == "net-02"),
        None,
    )
    if gray_trial and gray_trial["methods"]["tdn"]["proof_results"].get("gray connectivity") == "rejected":
        folder = (root / gray_trial["record"]).parent
        sections.append(
            "<p><b>Lean could check every possible route to the detached Gray Firewall.</b> "
            "On net-02 the firewall was the sole member of its connected region. The "
            "captured links showed that no edge entered that region from outside. A route "
            "of any length would need an entering edge to reach the firewall from an Inner "
            "gateway. Lean checked that argument and rejected the connectivity condition "
            "in TDN’s interpretation of RG-013.04. The same clause also covers the physical "
            "protection of classified equipment. That duty remains unexercised. Astra "
            "identified both missing interfaces and pointed out that the CP permits shared "
            "Gray infrastructure at a single security level. Its score records detection "
            "of the disconnection. Whether the CP requires that optional firewall to be "
            "connected on net-02 is a separate interpretation question. "
            + link(folder / "gray-links-observed.json", "Region in the live graph") + " "
            + link(HERE / "GrayConnectivityChecks.lean", "Proof for paths of any length", 72)
            + " " + link(folder / "astra/answer.md", "Astra’s reading of the CP", 7) + "</p>"
        )
    if len(sections) <= 3:
        return "".join(sections)
    return "".join(sections[:3]) + (
        "<details><summary>More findings from individual trials</summary>"
        + "".join(sections[3:]) + "</details>"
    )


def reader_access_table(rows, root):
    details = []
    requests = []
    by_observation = Counter()
    audits = completed = 0
    for method in ("astra", "sol"):
        calls = timeouts = 0
        for row in rows:
            folder = (root / row["record"]).parent / method
            audits += 1
            completed += json.loads((folder / "execution.json").read_text())["status"] == "completed"
            view = row["methods"][method]["observations"]
            calls += sum(view["query_count_by_network"].values())
            lost = sum(view["reader_timeouts_by_network"].values())
            timeouts += lost
            if not lost:
                continue
            log = folder / "events.jsonl"
            with log.open() as stream:
                for line_number, line in enumerate(stream, 1):
                    event = json.loads(line)
                    item = event.get("item", {})
                    message = (item.get("error") or {}).get("message", "")
                    if not (event["type"] == "item.completed" and item.get("tool") == "observe"
                            and item.get("status") == "failed" and "timed out" in message.lower()):
                        continue
                    args = item["arguments"]
                    by_observation[args["observation"]] += 1
                    devices = ", ".join(args.get("devices") or []) or "Network-wide request"
                    trial = f'{row["network"]} / {row["type"]}'
                    requests.append(
                        f'<tr><td>{NAME[method]}</td><td>{esc(trial)}</td><td>{esc(args["network"])}</td>'
                        f'<td><code>{esc(args["observation"])}</code></td><td>{esc(devices)}</td>'
                        f'<td>{link(log, "Request and timeout", line_number)}</td></tr>'
                    )
        details.append(
            f"<tr><th>{NAME[method]}</th><td>{calls}</td><td>{timeouts}</td></tr>"
        )
    request_table = ""
    if requests:
        most_frequent = " and ".join(
            f'<code>{esc(name)}</code> ({count})' for name, count in by_observation.most_common(2)
        )
        request_table = (
            f'<p>The most frequent requests to time out were {most_frequent}.</p>'
            f'<details><summary>Inspect all {len(requests)} timed-out requests</summary>'
            '<p>Each row names the network where the fault was injected and the network the Detector queried. '
            'A network-wide request asked the reader to select devices across that network.</p>'
            '<div class="tablewrap"><table><thead><tr><th>Detector</th><th>Trial</th><th>Network queried</th>'
            '<th>Requested data</th><th>Devices requested</th><th>Log entry</th></tr></thead>'
            f'<tbody>{"".join(requests)}</tbody></table></div></details>'
        )
    return (
        '<details id="query-timeouts"><summary>Which device queries timed out?</summary>'
        '<p>A single <code>reader/observe</code> request had <strong>5 minutes (300 seconds)</strong> '
        'to return. One request could cover several devices. After a timeout the Detector could issue another request. '
        'The <strong>1-hour (3,600-second)</strong> limit covered its entire audit, including time spent waiting. '
        f'{completed} of {audits} scored Detector audits finished. {link(HERE / "blind_audit.py", "Audit time limit in the launcher", 49)}</p>'
        '<div class="tablewrap"><table><thead><tr><th>Detector</th><th>Device queries</th>'
        '<th>Timed out at 5 minutes</th></tr></thead>'
        f'<tbody>{"".join(details)}</tbody></table></div>{request_table}</details>'
    )


def latency_chart(stats):
    available = [
        (m, stats[m]["median_seconds"])
        for m in METHODS
        if stats[m]["times_count"] and stats[m]["median_seconds"] > 0
    ]
    if not available:
        return "<p>Timing appears after a completed and scored live trial.</p>"
    low = math.floor(math.log10(min(v for _, v in available)))
    high = max(low + 1, math.ceil(math.log10(max(v for _, v in available))))
    loc = lambda x: 132 + 455 * (math.log10(x) - low) / (high - low)
    shapes = []
    for exponent in range(low, high + 1):
        x = loc(10**exponent)
        shapes.extend(
            [
                f'<line x1="{x}" y1="14" x2="{x}" y2="136" stroke="#dae3e8"/>',
                svgtext(x, 153, f"{10**exponent:g} s", 'text-anchor="middle"'),
            ]
        )
    for i, (m, v) in enumerate(available):
        y = 30 + 42 * i
        x = loc(v)
        shapes.extend(
            [
                svgtext(5, y + 5, NAME[m]),
                f'<line x1="132" y1="{y}" x2="{x}" y2="{y}" stroke="{COLORS[m]}" stroke-width="6"/>',
                f'<circle cx="{x}" cy="{y}" r="5.5" fill="{COLORS[m]}"/>',
                svgtext(610, y + 5, seconds(v)),
            ]
        )
    return (
        '<svg class="chart" viewBox="0 0 711 164" role="img" aria-label="Median time per trial on a logarithmic scale">'
        + "".join(shapes)
        + "</svg>"
    )


def complete_type_figure(types):
    complete = [
        group for group in types.values()
        if all(status not in ("pending", "inapplicable")
               for cells in group["cells"].values() for status in cells.values())
    ]
    if not complete:
        return ""
    case_count = len(complete) * len(NETWORKS)
    shapes = [
        '<defs><pattern id="assigned-credit-hatch" patternUnits="userSpaceOnUse" width="4" height="4">'
        '<rect width="4" height="4" fill="#eaedf6"/><path d="M-1 1L1 -1 M0 4L4 0 M3 5L5 3" '
        'stroke="#44516e" stroke-width="1.3"/></pattern></defs>'
    ]
    summaries = []
    for i, method in enumerate(METHODS):
        y = 29 + i * 52
        counts = Counter(status for group in complete for status in group["cells"][method].values())
        credits = sum(counts[status] for status in CREDITED)
        wins = sum(group["verdicts"][method] == "hit" for group in complete)
        summaries.append(f"{NAME[method]} earned {credits} of {case_count} network credits and full credit on {wins} of {len(complete)} types.")
        shapes.append(svgtext(4, y + 8, NAME[method]))
        for dy, value, total, label_text, opacity in (
            (0, credits, case_count, "network cases credited", ".48"),
            (20, wins, len(complete), "types with full credit", "1"),
        ):
            shapes.append(
                f'<rect x="104" y="{y + dy - 8}" width="225" height="12" rx="3" fill="#e9eef0"/>'
            )
            if value:
                shapes.append(
                    f'<rect x="104" y="{y + dy - 8}" width="{225 * value / total}" height="12" rx="3" fill="{COLORS[method]}" opacity="{opacity}"/>'
                )
            shapes.append(svgtext(345, y + dy + 3, f"{value}/{total} {label_text}"))
        if counts["assigned_credit"]:
            shapes.append(
                f'<rect x="{104 + 225 * counts["hit"] / case_count}" y="{y - 8}" '
                f'width="{225 * counts["assigned_credit"] / case_count}" height="12" fill="url(#assigned-credit-hatch)"/>'
            )
    return (
        '<figure id="detection-scores"><h3>Credit by network and by fault type</h3>'
        '<svg class="chart" style="max-width:660px" viewBox="0 0 550 166" role="img" '
        f'aria-label="{esc(" ".join(summaries))}">'
        + "".join(shapes)
        + "</svg><figcaption>The upper bar counts credited network cases. The hatched portion marks the point assigned to each method for the Gray Firewall case on net-02. The lower bar counts fault types that received credit on all four networks.</figcaption></figure>"
    )


def fault_matrix(types, snapshot_scores):
    snapshot_answers = (
        {(r["type"], r["network"]): r["new"] for r in snapshot_scores["rows"]}
        if snapshot_scores is not None else {}
    )
    groups = []
    for family, fault in types.items():
        title = esc(fault["title"])
        if any(cell in ("hit", "miss", "unevaluable", "timeout") for cell in fault["cells"]["tdn"].values()):
            title = f'<a href="#fault-{esc(family)}">{title}</a>'
        rows = []
        for method in METHODS:
            original = fault["cells"][method]
            rows.append((method, "Saved snapshot" if method == "tdn" else "Live network", original))
            if snapshot_scores is not None and method != "tdn":
                saved = {
                    network: original[network] if original[network] in ("assigned_credit", "inapplicable")
                    else snapshot_answers[family, network][method]["verdict"]
                    for network in NETWORKS
                }
                rows.append((method, "Saved snapshot", saved))

        body = []
        for index, (method, access, cells) in enumerate(rows):
            values = [cells[network] for network in NETWORKS]
            scored = [v for v in values if v not in ("inapplicable", "pending")]
            credits = sum(v in CREDITED for v in scored)
            rate = f"{credits} / {len(scored)}" if scored else "—"
            verdict = type_verdict(values)
            fault_heading = (
                f'<th scope="rowgroup" rowspan="{len(rows)}">{title}<small>{esc(", ".join(fault["clause_ids"]))}</small></th>'
                if index == 0 else ""
            )
            body.append(
                f'<tr>{fault_heading}<th scope="row">{NAME[method]}</th><td class="matrix-access">{access}</td>'
                + "".join("<td>" + tag(v) + "</td>" for v in values)
                + f'<td>{rate}</td><td>{tag(verdict, "Full credit" if verdict == "hit" else None)}</td></tr>'
            )
        groups.append("<tbody>" + "".join(body) + "</tbody>")

    columns = ("Fault type", "Method", "Access", *NETWORKS, "Network credits", "Four-network result")
    return (
        '<div class="matrix"><div class="tablewrap" role="region" aria-labelledby="fault-matrix-heading" tabindex="0">'
        '<table aria-labelledby="fault-matrix-heading"><thead><tr>'
        + "".join(f'<th scope="col">{esc(column)}</th>' for column in columns)
        + "</tr></thead>" + "".join(groups) + "</table></div></div>"
    )


def build(root, destination):
    if root.resolve() != PAIRED_SOURCE:
        from multilevel_report import build as current
        return current(root,destination)
    paired = root.resolve() == PAIRED_SOURCE and (SNAPSHOT_RUN / "score.json").is_file()
    data = json.loads((root/"score.json").read_text())
    snapshot_scores = json.loads((SNAPSHOT_RUN / "score.json").read_text()) if paired else None
    paired_panels = paired_report(root, SNAPSHOT_RUN, data, esc, link, seconds, result=snapshot_scores) if paired else {}
    scope = historical_json("clause_scope.json")
    rows = data["rows"]
    types = data["types"]
    stats = data["stats"]
    case_counts = stats["tdn"]["network_cases"]
    scored_slots = sum(case_counts.values()) - case_counts.get("inapplicable", 0)
    planned = scored_slots - case_counts.get("assigned_credit", 0)
    case_results = (
        f"Across {len(rows)} live trials, GPT-6 Astra identified {stats['astra']['trials'].get('hit', 0)} "
        f"changes, GPT-6 Sol identified {stats['sol']['trials'].get('hit', 0)}, and TDN produced "
        f"a related Lean type error for {stats['tdn']['trials'].get('hit', 0)}."
    )
    replayed = [row for row in rows if "tdn_recheck" in row]
    if replayed:
        new_hits = sum(row["methods"]["tdn"]["verdict"] == "hit" for row in replayed)
        case_results += (
            f' The TDN total includes {new_hits} detections from <a href="#protocol-253-rerun">'
            f'the {len(replayed)} snapshots rechecked after the importer fix</a>.'
        )
    control = json.loads((root / "control-ready.json").read_text())
    tested = {c for r in rows for c in r["clauses"]}
    scoped = Counter(v for e in scope.values() for v in e["scope"].values())
    group_table, coverage = coverage_table(scope, rows)
    inactive = inactive_table(scope)
    breakdown = historical_json("clause_branches.json")
    duty = duty_counts(scope, breakdown, rows)
    if breakdown.keys() - scope.keys():
        raise ValueError("Unknown requirement-group row in branch map")
    attempts = list((root / "attempts").glob("**/execution.json"))
    invalid_count = sum(
        json.loads(f.read_text()).get("status") == "invalid_run" for f in attempts
    )
    top = (
        '<div class="metrics">'
        + "".join(
            f"<div><strong>{v}</strong><span>{esc(k)}</span></div>"
            for v, k in [
                (len(NETWORKS), "original networks"),
                (len(rows), "live faults scored"),
                (f"{len({c.split('.')[0] for c in tested})} / {len({c.split('.')[0] for c in scope})}", "target groups exercised"),
                (f"{duty['observed']} / {duty['active']}", "applicable duties exercised across networks"),
            ]
        )
        + "</div>"
    )
    topology = []
    for n in control["networks"]:
        tunnels = [d for d in n["devices"] if d["role"] in ("inner", "outer")]
        topology.append(
            f"<tr><th>{esc(n['network'])}</th><td>{len(n['devices'])}</td><td>{sum(x['up'] and x['reciprocal'] for x in n['links'])}</td><td>{sum(d.get('installed', 0) > 0 for d in tunnels)} / {len(tunnels)}</td></tr>"
        )
    type_table = fault_matrix(types, snapshot_scores)
    clocktable = "".join(
        f"<tr><th>{NAME[m]}</th><td>{stats[m]['times_count']}</td><td>{seconds(stats[m]['median_seconds'])}</td><td>{seconds(stats[m]['min_seconds'])}</td><td>{seconds(stats[m]['max_seconds'])}</td></tr>"
        for m in METHODS
    )
    led = []
    clause_pointers = {}
    sources = json.loads((ROOT / "specs/requirement_clause_map.json").read_text())
    clause_doc = ROOT / "specs/requirement_clauses.md"
    guide_lines = clause_doc.read_text().splitlines()
    for cid, record in scope.items():
        applicable = [
            n
            for n, s in record["scope"].items()
            if s in ("applicable", "partly applicable")
        ]
        exercised = sorted({r["network"] for r in rows if cid in r["clauses"]})
        cells = ", ".join(exercised) if exercised else "—"
        branch = ", ".join(f"{n} ({s})" for n, s in record["scope"].items())
        duties = branch_details(cid, record, breakdown, rows)
        rg, index = cid.split(".")
        comparison = sources[rg]["clauses"][int(index) - 1]
        locations = [
            i
            for i, line in enumerate(guide_lines, 1)
            if line.startswith("|")
            and comparison["interpretation"] in line
            and comparison["counterexample"] in line
        ]
        line_number = locations[0] if len(locations) == 1 else None
        pointer = link(clause_doc, "Original clause and interpretation", line_number)
        clause_pointers[cid] = link(clause_doc, cid, line_number)
        led.append(
            f'<tr data-search="{esc((cid + " " + record["name"] + " " + record["scope_reason"] + " " + str(breakdown.get(cid, []))).lower())}" data-state="{"measured" if exercised else "open" if applicable else "conditional"}"><th>{cid}</th><td>{esc(record["name"])}<details><summary>Duties and evidence</summary><p>{esc(record["interpretation"])}</p>{duties}<p>{esc(record["scope_reason"])}</p><p>{pointer}</p><small>{esc(branch)}</small></details></td><td>{len(applicable)} / 4</td><td>{cells}</td></tr>'
        )
    descriptions = historical_json("violation_descriptions.json")
    if descriptions.keys() != types.keys():
        raise ValueError("The violation guide and the registered fault types must agree")
    fault_cards, trial_descriptions = violation_catalog(rows, types, descriptions, clause_pointers)
    casecards = []
    for r in rows:
        folder = (root / r["record"]).parent
        details = []
        for m in METHODS:
            v = r["methods"][m]
            source = link(folder / v["source"], "Evidence", v.get("lines", [None])[0])
            rejected = [
                key
                for key, status in v.get("proof_results", {}).items()
                if status == "rejected"
            ]
            modules = (
                (" Lean rejected " + ", ".join(rejected) + ".") if rejected else ""
            )
            query_note = ""
            if m in ("astra","sol"):
                seen = v["observations"]
                settings = seen["visible_target_settings"]
                ops = seen["target_operations_visible"]
                if settings:
                    query_note = "<small>The returned pages contain " + esc(", ".join(settings)) + ".</small>"
                elif ops:
                    query_note = "<small>Recorded queries returning rows for " + esc(r["target"]) + " included " + esc(", ".join(ops)) + ".</small>"
            elif v.get("proof_seconds"):
                timings = " ".join(f"<li>{esc(name)} <b>{esc(seconds(value))}</b></li>" for name,value in v["proof_seconds"].items())
                query_note = "<details><summary>Measured Lean time by check</summary><ul>" + timings + "</ul></details>"
            sentences = v["reason"].split("; ")
            reason = ". ".join(s[:1].upper() + s[1:] for s in sentences)
            details.append(
                f"<tr><th>{NAME[m]}</th><td>{tag(v['verdict'])}</td><td>{esc(method_time(m, v))}</td><td>{esc(reason + modules)} {source}{query_note}</td></tr>"
            )
        session_order = folder / "observed-session-order.json"
        timing_note = ""
        if session_order.is_file():
            timing_note = (
                "<p>The snapshot recorded an installed tunnel at both Inner gateways. "
                "Later, during the same firewall change, both Detectors queried those "
                "gateways and found no active tunnel. The blocked packet exchange was "
                "already visible in the earlier capture. "
                + link(session_order, "Observation times and original answer logs")
                + "</p>"
            )
        peer_control = folder / "fresh-peer-control.json"
        peer_fault = folder / "fresh-peer-fault.json"
        if peer_control.is_file() and peer_fault.is_file():
            timing_note += (
                "<p>Both gateways established the intended cross-site tunnel in the clean "
                "control. With the local address loaded as the remote peer, the same "
                "negotiation left both gateways without the intended tunnel. "
                + link(peer_control, "Clean negotiation") + " "
                + link(peer_fault, "Negotiation during the trial") + "</p>"
            )
        family, network = r["type"], r["network"]
        variant = trial_descriptions[family, network]
        record_links = [
            link(folder / "change.json", "Recorded change"),
            link(folder / descriptions[family]["observation"], "Live observation"),
            link(folder / "events.jsonl", "Trial timeline"),
            link(folder / "restoration.json", "Restoration check"),
        ]
        casecards.append(
            f'<details class="trial-case" id="trial-{esc(family)}-{esc(network)}">'
            f'<summary>{esc(network)} / {esc(types[family]["title"])}</summary>'
            f'<dl class="fault-facts"><dt>Requirement <a href="#fault-{esc(family)}">{esc(", ".join(r["clauses"]))}</a></dt>'
            f'<dd>{esc(variant["requirement"])}</dd><dt>Injected change on <code>{esc(r["target"])}</code></dt>'
            f'<dd>{esc(variant["change"])}</dd>{trial_change_field(folder, r)}'
            f'<dt>Live observation</dt><dd>{esc(r["oracle"])}</dd></dl>'
            '<div class="tablewrap"><table><thead><tr><th>Method</th><th>Result</th><th>Time</th>'
            f'<th>What establishes the score</th></tr></thead><tbody>{"".join(details)}</tbody></table></div>'
            f'{timing_note}<p class="record-links">{" ".join(record_links)}</p></details>'
        )
    source_links = " &nbsp; ".join(
        [
            link(ROOT / "specs/requirement_formalizations.md", "Ten proof targets", 7),
            link(ROOT / "specs/requirement_clauses.md", "Source-to-clause guide"),
            link(HERE / "clause_scope.json", "Applicability ledger"),
            link(root / "score.json", "Scores and timings"),
            link(
                root / "protocol.json", "Exact source versions and clean proof hashes"
            ),
            link(HERE / "blind_audit.py", "Detector launcher"),
            link(HERE / "measure.py", "Lean timing code"),
        ]
    )
    validation = root / "validation.json"
    if validation.is_file():
        source_links += " &nbsp; " + link(validation, "Verified trial intervals and capture counts")
    fact = (
        "The four original deployments provide "
        + str(sum(len(n["devices"]) for n in control["networks"]))
        + " devices and "
        + str(sum(len(n["links"]) for n in control["networks"]))
        + " declared links. All 36 tunnel endpoints had installed associations after certificate renewal."
    )
    note = (
        "The first access check lacked read permission on the audit tools. The network was restored, the three reader tools were explicitly marked read-only, and a separate access test verified the connection before the scored retry."
        if invalid_count
        else ""
    )
    css = """
    :root{color-scheme:light;--bg:#f5f8fa;--panel:#fff;--ink:#172c3b;--muted:#496271;--line:#cfdae1;--accent:#086b7c;--soft:#e8f3f3}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1140px;margin:auto;padding:30px clamp(16px,5vw,60px) 70px}h1{font-size:clamp(2rem,4.5vw,3.6rem);letter-spacing:-.045em;line-height:1.04;margin:.45em 0}h2{font-size:1.7rem;line-height:1.2;margin:.1rem 0 1rem}h3{font-size:1.16rem}p{max-width:82ch}section,header{margin-bottom:24px;padding:clamp(18px,3vw,32px);background:var(--panel);border:1px solid var(--line);border-radius:14px;min-width:0}header{border-top:5px solid var(--accent)}a{color:var(--accent);overflow-wrap:anywhere;text-underline-offset:3px}small{display:block;color:var(--muted);font-weight:400}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:24px 0 6px}.metrics>div{border-top:2px solid var(--accent);padding:10px 3px}.metrics strong{font-size:2.1rem;display:block;line-height:1.15}.metrics span{font-size:.93rem;color:var(--muted)}.tablewrap{max-width:100%;overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.91rem}th,td{text-align:left;vertical-align:top;padding:9px 8px;border-bottom:1px solid var(--line)}thead th{color:var(--muted);font-size:.8rem}td{overflow-wrap:anywhere}.tag{display:inline-block;font-size:.76rem;padding:2px 7px;border-radius:6px;background:#eaf0f3;color:#465f6f;white-space:nowrap}.hit{background:#d9eeea;color:#155f4a}.miss{background:#ffe4dd;color:#8b3426}.unevaluable{background:#f8edcb;color:#785d16}.chart{display:block;width:100%;max-width:760px;height:auto}.chart text{fill:var(--ink);font-family:inherit;font-size:13px}.sidenote{color:var(--muted);font-size:.9rem}details{border-bottom:1px solid var(--line);padding:9px 0}td details{border:0;font-size:.86rem}summary{cursor:pointer;color:var(--accent);font-weight:600}input,select{font:inherit;max-width:100%;padding:7px 10px;border:1px solid var(--line);border-radius:6px;color:var(--ink);background:var(--panel)}.filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}figure{margin:14px 0}figcaption{color:var(--muted);font-size:.88rem}.source{overflow-wrap:anywhere}.two{display:grid;gap:20px;grid-template-columns:repeat(2,minmax(0,1fr))}@media(max-width:720px){main{padding:12px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.two{grid-template-columns:1fr}th,td{padding:6px;font-size:.82rem}section,header{padding:14px}.tag{padding:2px 4px}.matrix table{min-width:610px}}@media print{nav,.filters{display:none}section,header{border:0;padding:8px}body{background:white}}
    """
    css += """
    .tag.assigned_credit { background:#eef0f8; color:#374266; border:1px dashed #74809c; white-space:normal; }
    details:not([open]) > :not(summary) { display:none; }
    .report-contents { display:block; position:fixed; right:max(14px, env(safe-area-inset-right)); bottom:max(14px, env(safe-area-inset-bottom)); z-index:5; margin:0; font-size:.93rem; }
    .report-contents details { position:relative; margin:0; padding:0; border:0; }
    .report-contents summary { display:flex; align-items:center; justify-content:space-between; gap:1rem; min-height:44px; padding:.6rem 1rem; list-style:none; border-radius:.65rem; color:white; background:var(--accent); box-shadow:0 2px 10px #172c3b30; }
    .report-contents summary::-webkit-details-marker { display:none; }
    .report-contents summary::after { content:""; width:.45rem; height:.45rem; border-right:2px solid; border-bottom:2px solid; transform:rotate(225deg); }
    .report-contents details[open] summary::after { transform:rotate(45deg); }
    .report-contents ul { list-style:none; position:absolute; right:0; bottom:calc(100% + .4rem); min-width:12rem; max-height:65vh; max-height:65dvh; overflow:auto; margin:0; padding:.35rem; background:var(--panel); border:1px solid var(--line); border-radius:.65rem; box-shadow:0 3px 16px #172c3b20; }
    .report-contents a { display:flex; align-items:center; min-height:40px; padding:.45rem .65rem; color:var(--ink); border-left:3px solid transparent; text-decoration:none; }
    .report-contents a[aria-current="location"] { font-weight:650; border-color:var(--accent); color:var(--accent); background:var(--soft); }
    .report-contents a:hover { text-decoration:underline; }
    a:focus-visible, summary:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
    main [id] { scroll-margin-block-start:1rem; }
    .fault-list { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,22rem),1fr)); gap:1rem; }
    .fault-card { min-width:0; padding:1rem; border:1px solid var(--line); border-radius:.65rem; }
    .fault-card h3 { margin:.3rem 0 .75rem; line-height:1.35; }
    .fault-card h4 { margin:1rem 0 .4rem; }
    .fault-facts { margin:.7rem 0; }
    .fault-facts dt { margin-top:.8rem; font-weight:650; }
    .fault-facts dd { margin:.15rem 0 0; max-width:75ch; }
    .trial-links, .record-links { display:flex; flex-wrap:wrap; gap:.25rem .9rem; }
    .trial-links a { font-size:.9rem; }
    .case-values { margin:.2rem 0; padding-left:1.35rem; overflow-wrap:anywhere; }
    .trial-case:target > summary { text-decoration:underline; text-underline-offset:3px; }
    @media (min-width:62rem) {
      .report-layout { display:grid; grid-template-columns:10.5rem minmax(0,64rem); gap:clamp(1rem,2vw,2rem); align-items:start; justify-content:center; max-width:85rem; margin:auto; padding:30px clamp(16px,2vw,32px) 70px; }
      .report-layout > main { width:100%; min-width:0; max-width:none; margin:0; padding:0; }
      .report-contents { position:sticky; top:1rem; right:auto; bottom:auto; }
      .report-contents details { background:var(--panel); border:1px solid var(--line); border-radius:.65rem; }
      .report-contents summary { background:transparent; box-shadow:none; color:var(--ink); }
      .report-contents summary::after { transform:rotate(45deg); }
      .report-contents details[open] summary::after { transform:rotate(225deg); }
      .report-contents ul { position:static; min-width:0; max-height:calc(100vh - 6rem); max-height:calc(100dvh - 6rem); border:0; border-top:1px solid var(--line); border-radius:0 0 .65rem .65rem; box-shadow:none; }
    }
    @media (max-width:61.99rem) { .report-layout > main { padding-bottom:5rem; } }
    @media print { .report-contents { display:none; } .report-layout { display:block; padding:0; } .fault-card { break-inside:avoid; } }
    """
    sections = [("overview", "Overview")]
    if paired:
        sections.extend([("snapshot-results", "Live vs. snapshot"), ("astra-misses", "Astra’s misses")])
        css += """
        .mini-track{width:clamp(30px,5vw,76px);height:8px;display:inline-block;margin:0 .6em .12em 0;background:#e0ebed;border-radius:3px;overflow:hidden}
        .mini-track i{height:100%;display:block;background:#147181}.fault-card h5{font-size:1rem;margin:.5rem 0}
        #astra-misses .fault-card{margin:.7rem 0 1rem} #snapshot-results th,#snapshot-results td{font-variant-numeric:tabular-nums}
        #astra-misses blockquote{margin:.6rem 0;padding:.35rem .7rem;border-left:3px solid var(--line);color:var(--muted);font-size:.9rem;overflow-wrap:anywhere} #astra-misses code{overflow-wrap:anywhere} #snapshot-results details summary{min-height:32px}
        """
    sections.extend([
        ("results", "Live detection" if paired else "Detection"),
        ("fault-matrix", "Results by fault and network"),
        ("time", "Live timing" if paired else "Runtime"),
        ("violations", "Violations tested"), ("cases", "Trial evidence"), ("proofs", "Lean proofs"),
        ("coverage", "Clause coverage"), ("method", "Method"),
    ])
    css += """
    .matrix tbody + tbody tr:first-child > * { border-top:2px solid var(--line); }
    .matrix .matrix-access { overflow-wrap:normal; }
    @media (max-width:720px) {
      .matrix th[scope="rowgroup"] { min-width:9rem; }
      .matrix .matrix-access { min-width:5.25rem; }
    }
    """
    contents = "".join(f'<li><a href="#{anchor}">{label}</a></li>' for anchor, label in sections)
    navigation_script = """
    const toc = document.querySelector(".report-contents details");
    const wide = window.matchMedia("(min-width:62rem)");
    const links = Array.from(toc.querySelectorAll("a"));
    const sections = links.map(link => document.querySelector(link.hash));
    function markSection() {
      let current = 0;
      for (let i = 1; i < sections.length; i++) {
        if (sections[i].getBoundingClientRect().top <= 64) current = i;
      }
      if (window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2) current = sections.length - 1;
      links.forEach((link, i) => {
        if (i === current) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      });
    }
    function showAnchor() {
      const target = document.getElementById(window.location.hash.slice(1));
      if (target instanceof HTMLDetailsElement && !target.open) {
        target.open = true;
        target.scrollIntoView();
      }
      markSection();
    }
    function layoutContents() { toc.open = wide.matches; markSection(); }
    wide.addEventListener("change", layoutContents);
    document.addEventListener("click", event => {
      const link = event.target.closest('a[href^="#"]');
      if (link) {
        const target = document.getElementById(link.hash.slice(1));
        if (target instanceof HTMLDetailsElement) target.open = true;
      }
      if (!wide.matches && (link || !toc.contains(event.target))) toc.open = false;
    });
    document.addEventListener("keydown", event => {
      if (event.key === "Escape" && toc.open && !wide.matches) {
        toc.open = false;
        toc.querySelector("summary").focus();
      }
    });
    window.addEventListener("scroll", markSection, { passive:true });
    window.addEventListener("hashchange", showAnchor);
    window.addEventListener("resize", markSection);
    layoutContents();
    showAnchor();
    """
    access_intro = ("The original Detectors queried four running networks during each one-fault trial. The new Detectors audited the same faults using saved snapshots. Both pairs received the original CSfC document."
                    if paired else "Each live trial changes one network. Each Detector inspects all four.")
    doc = f"""<!doctype html><html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><title>TDN v3.4 | Blind audits of four MSC networks</title><style>{css}</style></head><body><div class="report-layout">
<nav aria-label="Table of contents" class="report-contents"><details><summary>Contents</summary><ul>{contents}</ul></details></nav>
<main><header id="overview"><small>TDN v3.4 / Network verification experiments</small><h1>Blind audits of four MSC networks</h1><p>{access_intro} The comparison scores {len(types)} fault types across {len(NETWORKS)} networks, for {scored_slots} network cases per method.</p><p>The experiment completed {len(rows)} of {planned} applicable trials. Each method also receives one assigned point for RG-040.07 on net-02. That network has one security level, so the Gray Firewall requirement does not apply.</p>{top}<p>{paired_panels.get("summary","")}</p><p class="sidenote">A duty is one condition within a requirement. The coverage count includes that duty once for each network where it applies.</p></header>
{paired_panels.get("comparison","")}{paired_panels.get("misses","")}
<section id="results"><h2>{"Live Detectors and TDN on the original trials" if paired else "Which changes did each method find?"}</h2><p>{case_results}</p>{complete_type_figure(types)}{takeaways(rows, root)}</section>
<section id="fault-matrix"><h2 id="fault-matrix-heading">Results by fault and network</h2><p>{"Astra and Sol each audited the same fault twice, once on the live network and once from its saved snapshot. TDN checked the saved snapshot." if paired else "Astra and Sol inspected the live networks. TDN checked their saved snapshots."}</p><p class="sidenote">Each observed detection earns one point. “Assigned credit” marks the unrun Gray Firewall case on net-02. Four credited networks earn full credit for a fault type.</p>{type_table}</section>
<section id="time"><h2>{"Time for the original live audits and TDN typechecks" if paired else "Time to finish an audit or typecheck"}</h2><figure>{latency_chart(stats)}<figcaption>Median time across the scored trials shown below. Each tick on the horizontal axis multiplies time by ten.</figcaption></figure><table><thead><tr><th>Method</th><th>Timed trials</th><th>Median</th><th>Shortest</th><th>Longest</th></tr></thead><tbody>{clocktable}</tbody></table><p>The Detector clock includes reading the PDF, issuing network queries and producing its final answer. The Lean clock starts after evidence loading and covers the fixed proof commands. The trial records preserve each module’s measured interval.</p>{timings_on_same_trials(rows)}{elapsed_figure(root)}{times_by_network(rows, root)}{reader_access_table(rows, root)}</section>
<section id="violations"><h2>Violations tested</h2><p>The {len({r["type"] for r in rows})} fault types below account for {len(rows)} live trials. Each entry gives the requirement and the change made to the network. Select a device to see the before-and-after evidence and how each method scored.</p><div class="fault-list">{fault_cards}</div></section>
<section id="cases"><h2>Evidence for each live trial</h2>{"".join(casecards)}{attempt_notes(root)}</section>{proof_panel(root)}
<section id="coverage"><h2>Which clauses apply to each network?</h2><p>The ten target groups contain {len(scope)} rows in the clause guide. Each row is counted once per network. A row can contain several duties. For example, selecting the wrong ESP mode tests one duty in RG-029.01. The same row also requires an associated IP tunnel.</p><p>{coverage["exercised"]} network–clause combinations have an observed fault. Another {coverage["open"]} have an applicable duty without a measured live violation. On {scoped.get("inapplicable", 0)} combinations the condition needed to exhibit the violation is absent from the original profile. The remaining {scoped.get("selection unconfirmed", 0)} depend on an objective that the profiles do not record.</p>{group_table}{inactive}<p>The clause breakdown contains {duty["entries"]} individual duties. Across the four networks, {duty["active"]} duty–network pairs apply. Of those, {duty["observed"]} have a measured live violation and {duty["active"] - duty["observed"]} remain unexercised. Another {duty["inactive"]} have an inactive condition and {duty["undecided"]} depend on an unconfirmed objective.</p>
<div class="filters"><input id="search" type="search" aria-label="Find a clause" placeholder="Find a clause or requirement"><select id="state" aria-label="Filter coverage"><option value="">All rows</option><option value="measured">At least one measured trial</option><option value="open">Applicable, unexercised</option><option value="conditional">Conditional or unconfirmed</option></select></div><div class="tablewrap"><table id="ledger"><thead><tr><th>Clause</th><th>Duty</th><th>Applies on</th><th>Exercised on</th></tr></thead><tbody>{"".join(led)}</tbody></table></div></section>
<section id="method"><h2>How the original live comparison was run</h2><p>{esc(fact)}</p>{profile_figure(control)}<div class="two"><div><h3>Networks at the start</h3><table><thead><tr><th>Profile</th><th>Devices</th><th>Links up</th><th>Tunnel endpoints installed</th></tr></thead><tbody>{"".join(topology)}</tbody></table></div><div><h3>Inputs to each method</h3><p>Each trial runs GPT-6 Astra and GPT-6 Sol independently, both with high reasoning effort. Each Detector starts a fresh session with the original PDF and read-only access to the four networks. TDN checks the affected network’s capture. Its Outer Firewall proof also receives the experiment’s recorded approval for Black-side OSPF. The blind Detectors must substantiate a finding from the PDF and the device state available through their reader. The supervisor runs the active delivery probes and keeps their results, mutation records and earlier answers outside the Detector’s tools.</p></div></div>{control_notes(root)}<p>Codex acted as the supervisor. After restoration, it read each complete answer, compared it with the observed change, and recorded the relevant lines. A finding earns credit when its description establishes the specific change. A different requirement number is acceptable. The revised scoring rule gives every method one additional point for the unrun net-02 Gray Firewall case. Timing and coverage use only live trials. Precision over every reported finding would require independent judgments on the other observations, including problems that existed before the trial. A Lean error earns credit when a matching clean proof passed and the failure follows from the change. Import failures, missing observations and invalid Detector sessions have their own outcomes.</p><p>{esc(note)}</p><p class="source">{source_links}</p></section>
</main></div><script>{navigation_script}</script><script>function filter(){{const text=document.querySelector("#search").value.toLowerCase(),state=document.querySelector("#state").value;for(const row of document.querySelectorAll("#ledger tbody tr"))row.hidden=!(row.dataset.search.includes(text)&&(!state||row.dataset.state===state));}}document.querySelector("#search").addEventListener("input",filter);document.querySelector("#state").addEventListener("change",filter);</script></body></html>"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(doc)
    return destination


if __name__ == "__main__":
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("run", type=Path)
    a.add_argument(
        "--out", type=Path
    )
    x = a.parse_args()
    output = x.out or ROOT / ".lavish" / ("naive-agent-rg-baseline.html" if x.run.resolve() == PAIRED_SOURCE else "naive-agent-multilevel.html")
    print(build(x.run.resolve(), output.resolve()))
