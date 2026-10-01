#!/usr/bin/env python3
"""Render readable ASP facts and check the pinned MSC model with clingo.

The base must have exactly one stable model. Each named property is then checked
by asking for a stable model containing its violation. SAT yields a witness;
UNSAT establishes absence only within the documented finite/structural scope.
No live node is contacted. No Lean proof certificate is produced.
"""

import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import time

try:
    import clingo
except ImportError as exc:
    raise SystemExit("Use .venv-asp/bin/python after installing asp/requirements.txt") from exc

from import_msc_snapshot import load_snapshot
from run_msc_datalog import packet_cases

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "asp/MSC"
DEFAULT_SNAPSHOT = ROOT / "artifacts/msc-node1-model/snapshot"
DEFAULT_CHECKS = ROOT / "artifacts/msc-node1-model/check.json"
MUTATIONS = ["gray-bypass", "unguarded-encryptor", "gray-default-accept", "cross-level-authorization", "missing-sa"]
RELATIONS = {"gray_reach": "GrayReach", "management_reach": "ManagementReach",
             "decision": "Decision", "transmitted": "Transmitted", "delivered": "Delivered"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def coverage():
    rows = json.loads((MODEL / "coverage.json").read_text())
    names = [row["theorem"] for row in rows]
    actual = [name for path in (ROOT / "TDN/MSC").glob("*.lean")
              for name in re.findall(r"^theorem (\w+)", path.read_text(), re.M)]
    queries = set(re.findall(r"violation\(([a-z_]+),", (MODEL / "properties.lp").read_text()))
    if len(names) != len(set(names)) or not set(names) <= set(actual) or set(names) != queries:
        raise ValueError("ASP baseline must map existing MSC theorems and named violation queries exactly once")
    return rows


def unmapped_lean_theorems():
    """Report the later Lean contracts outside the original ASP comparison."""
    mapped = {row["theorem"] for row in coverage()}
    actual = {name for path in (ROOT / "TDN/MSC").glob("*.lean")
              for name in re.findall(r"^theorem (\w+)", path.read_text(), re.M)}
    return sorted(actual - mapped)


def q(value):
    return str(clingo.String(value))


def constant(value):
    if not re.fullmatch(r"[a-z][a-z0-9_]*", value):
        raise ValueError(f"invalid ASP constant: {value}")
    return value


def ipv4(value):
    octets = str(ipaddress.IPv4Address(value)).split(".")
    return "ipv4(" + ",".join(octets) + ")"


def tag(value):
    if value is None or value == -1:
        return "none"
    if value < 0 or value > 2**31 - 1:
        raise ValueError("policy ID outside clingo integer domain")
    return f"some({value})"


def query_cases(data):
    cases = []
    for table in data["tables"]:
        for index, rule in enumerate(table["rules"]):
            cases.extend(packet_cases(table["device"], index, rule))
    cases.extend([
        ["esp", "OF_A1", "inside", "outside", 2886994689, 2886997249, 50, 0, -1, -1],
        ["icmp", "OF_A1", "inside", "outside", 2886994689, 2886997249, 1, 0, -1, -1],
        ["wrong-peer", "OF_A1", "inside", "outside", 2886994689, 2886997505, 50, 0, -1, -1],
        ["unknown", "unknown-device", "inside", "outside", 0, 0, 1, 0, -1, -1]])
    return cases


def mutate(data, mutation):
    """Modify a copied normalized input, leaving all original artifacts intact."""
    if mutation == "gray-bypass":
        data["spec"]["links"].append({"a": {"device": "I_A1", "interface": "gray"},
                                     "b": {"device": "I_A2", "interface": "gray"}})
    elif mutation == "unguarded-encryptor":
        table = next(t for t in data["tables"] if t["device"] == "I_A1")
        table["rules"][0].pop("inPolicy", None)
        table["rules"][0].pop("outPolicy", None)
    elif mutation == "gray-default-accept":
        next(t for t in data["tables"] if t["device"] == "GF_A")["defaultAccept"] = True
    elif mutation == "cross-level-authorization":
        data["authorized_pairs"].append(("R_A1", "R_B2"))
    elif mutation == "missing-sa":
        data["tunnel_observations"]["I_A1"] = None
    elif mutation is not None:
        raise ValueError(f"unknown mutation: {mutation}")


def render_facts(data, evidence, mutation=None):
    lines = ["% Generated from the pinned node-1 snapshot; regenerate rather than edit.",
             "% Declared topology, observed filters, derived inputs, and observations are separated below.",
             f"% Mutation: {mutation or 'none (baseline)'}. Synthetic mutations are not observations.", ""]

    def fact(name, *values):
        lines.append(f"{name}({', '.join(values)}).")

    interfaces = {}
    lines.append("% DECLARED DEVICES: device(Name, Role, Site, SecurityLevel).")
    for index, device in enumerate(data["spec"]["devices"]):
        name = device["id"]
        site = q(device["site"]) if device.get("site") else "none"
        level = q(device["level"]) if device.get("level") in {"S1", "S2"} else "none"
        lines.extend(["", f"% {name}"])
        fact("device", q(name), constant(device["role"].replace("-", "_")), site, level)
        fact("device_row", str(index), q(name))
        fact("management_domain", q(name), q(data["domains"][name]) if name in data["domains"] else "none")
        if device.get("admin"):
            fact("administrator_address", q(name), q(device["admin"]))
        for port in device["interfaces"]:
            interfaces[name, port["name"]] = port
            fact("interface", q(name), q(port["name"]), constant(port["zone"]), q(port.get("address", "")))
        for route in device.get("routes", []):
            fact("route", q(name), q(route["prefix"]), q(route["via"]))
        if device.get("tunnel"):
            t = device["tunnel"]
            fact("tunnel", q(name), *[q(t[k]) for k in ["peer", "local", "remote", "local_ts", "remote_ts", "trust"]], str(t["reqid"]))
    lines.extend(["", "% DECLARED CABLES: link(Row, DeviceA, PortA, DeviceB, PortB, Zone)."])
    for index, link in enumerate(data["spec"]["links"]):
        a, b = link["a"], link["b"]
        fact("link", str(index), q(a["device"]), q(a["interface"]), q(b["device"]), q(b["interface"]), constant(interfaces[a["device"], a["interface"]]["zone"]))
    lines.extend(["", "% OBSERVED FORWARD FILTERS: named matches, optional fields omitted for wildcards.",
                  "% Rules are ACCEPT-only; requires_policy names the kernel-derived IPsec tag.",
                  "% IPv4 ranges use readable octets and avoid signed 32-bit integer overflow."])
    for table in data["tables"]:
        name = q(table["device"])
        lines.append("")
        fact("forward_table", name, "accept" if table["defaultAccept"] else "drop")
        for index, rule in enumerate(table["rules"]):
            row = str(index)
            fact("forward_rule", name, row)
            for field, predicate in [("input", "input_interface"), ("output", "output_interface")]:
                if field in rule:
                    fact(predicate, name, row, q(rule[field]))
            for field in ["source", "destination"]:
                if field in rule:
                    network = ipaddress.IPv4Network(rule[field])
                    lines.append(f"% {field}: {network}")
                    fact(field + "_range", name, row, ipv4(network.network_address), ipv4(network.broadcast_address))
            if "protocol" in rule:
                fact("protocol", name, row, str(rule["protocol"]))
            for port in rule.get("destinationPorts", []):
                fact("destination_port", name, row, str(port))
            for field, direction in [("inPolicy", "in"), ("outPolicy", "out")]:
                if field in rule:
                    tag(rule[field])
                    fact("requires_policy", name, row, direction, str(rule[field]))
    lines.extend(["", "% DERIVED AUTHORIZATION: from declared inner peers and Red attachments.",
                  "% These pairs do not independently establish organization policy approval."])
    for source, destination in data["authorized_pairs"]:
        fact("authorized", q(source), q(destination))
    lines.extend(["", "% SAMPLED OBSERVATIONS: device, timestamp, running, spec hash, error count, tunnel state.",
                  "% unknown is different from not_established and is never inferred healthy."])
    for o in data["status"]["devices"]:
        up = data["tunnel_observations"][o["device"]]
        tunnel = "unknown" if up is None else "established" if up else "not_established"
        fact("observation", q(o["device"]), q(o["observed_at"]), "true" if o["state"] == "running" else "false",
             q(o["deployed_spec_sha256"]), str(len(o.get("errors", {}))), tunnel)
    lines.extend(["", "% EVIDENCE IDENTITY: specification, manifest, probe hashes, count, pass flag."])
    fact("evidence", q(evidence["spec_sha256"]), q(evidence["manifest_sha256"]), q(evidence["checks_sha256"]),
         str(evidence["probe_count"]), str(int(evidence["probes_passed"])))
    lines.extend(["", "% CHECK CATALOG: these names request checks; they do not assert truth."])
    for row in coverage():
        fact("property", constant(row["theorem"]), constant(row["scope"].replace("-", "_").replace(" ", "_")))
    return "\n".join(lines) + "\n"


def render_cases(cases):
    lines = ["% Generated regression packets, NOT captured traffic or exhaustive packet enumeration.",
             "% packet_case(Id, Device, Input, Output, Source, Destination, Protocol, DstPort, InPolicy, OutPolicy)."]
    for row in cases:
        values = [*[q(v) for v in row[:4]], ipv4(row[4]), ipv4(row[5]),
                  str(row[6]), str(row[7]), tag(row[8]), tag(row[9])]
        lines.append("packet_case(" + ", ".join(values) + ").")
    return "\n".join(lines) + "\n"


def prepare(snapshot=DEFAULT_SNAPSHOT, checks=DEFAULT_CHECKS, mutation=None):
    data = load_snapshot(snapshot, checks)
    cases = query_cases(data)
    evidence = {"spec_sha256": data["spec_hash"], "manifest_sha256": sha(snapshot / "manifest.json"),
                "checks_sha256": sha(checks), "probe_count": len(data["checks"]["checks"]),
                "probes_passed": bool(data["checks_passed"])}
    data = copy.deepcopy(data)
    mutate(data, mutation)
    return render_facts(data, evidence, mutation), render_cases(cases), cases, evidence


def symbol_value(symbol):
    if symbol.type == clingo.SymbolType.String:
        return symbol.string
    return str(symbol)


def relations(symbols):
    result = {}
    for atom in symbols:
        result.setdefault(atom.name, []).append([symbol_value(a) for a in atom.arguments])
    return {name: sorted(rows) for name, rows in sorted(result.items())}


def solve(control, timeout):
    models = []
    with control.solve(async_=True, on_model=lambda model: models.append(model.symbols(shown=True))) as handle:
        if not handle.wait(timeout):
            handle.cancel()
            raise TimeoutError(f"clingo solving exceeded {timeout} seconds")
        result = handle.get()
    if result.unknown or result.interrupted:
        raise RuntimeError("clingo returned unknown/interrupted, not a completed result")
    return result, models


def evaluate(facts, cases, *, program=MODEL / "msc.lp", timeout=60, queries=True):
    diagnostics = []
    control = clingo.Control(["--models=2", "--stats=2"], logger=lambda code, message: diagnostics.append(str(message)))
    started = time.perf_counter()
    control.load(str(program))
    control.add("base", [], facts + "\n" + cases)
    control.ground([("base", [])])
    ground_seconds = time.perf_counter() - started
    started = time.perf_counter()
    result, models = solve(control, timeout)
    base_seconds = time.perf_counter() - started
    if not result.satisfiable or not result.exhausted or len(models) != 1:
        raise ValueError("base must have exactly one complete stable model; inconsistency/ambiguity is not proof")
    base = relations(models[0])
    stats = {k: int(v) for k, v in base.get("statistics", [])}
    expected = {row["theorem"] for row in coverage()}
    result_rows = base.get("result", [])
    if {row[0] for row in result_rows} != expected or len(result_rows) != len(expected):
        raise ValueError("missing or duplicate property results")
    if stats.get("states") != 512 or stats.get("host_pairs") != 16:
        raise ValueError("state or host domain is incomplete")
    if any(row[0] not in expected for row in base.get("violation", [])):
        raise ValueError("unmapped property violation")
    ground_stats = copy.deepcopy(control.statistics)
    checks = []
    started = time.perf_counter()
    for name, status, scope in result_rows:
        check = {"name": name, "status": status, "scope": scope}
        if queries:
            external = clingo.Function("check", [clingo.Function(name)])
            control.assign_external(external, True)
            query_result, witnesses = solve(control, timeout)
            control.assign_external(external, False)
            expected_sat = status == "fail"
            if bool(query_result.satisfiable) != expected_sat:
                raise ValueError(f"counterexample query disagrees with base result: {name}")
            check["counterexample_query"] = "SAT" if query_result.satisfiable else "UNSAT"
            check["witnesses"] = relations(witnesses[0]).get("counterexample", []) if witnesses else []
            if expected_sat and not check["witnesses"]:
                raise ValueError("SAT counterexample query produced no witness")
        checks.append(check)
    return {"relations": base, "answer_set": sorted(str(atom) + "." for atom in models[0]),
            "checks": checks, "statistics": stats,
            "base_stable_models": 1, "diagnostics": diagnostics, "clingo_statistics": ground_stats,
            "timing_seconds": {"load_parse_ground": ground_seconds, "base_solve_and_extract": base_seconds,
                               "all_counterexample_queries": time.perf_counter() - started}}


def run_model(snapshot=DEFAULT_SNAPSHOT, checks=DEFAULT_CHECKS, output=None, mutation=None, timeout=60):
    output = Path(output or ROOT / "artifacts/msc-node1-asp")
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps({"completed": False}) + "\n")
    started = time.perf_counter()
    facts, cases, _, evidence = prepare(snapshot, checks, mutation)
    (output / "facts.lp").write_text(facts)
    (output / "packet_cases.lp").write_text(cases)
    import_seconds = time.perf_counter() - started
    evaluation = evaluate(facts, cases, timeout=timeout)
    output_relations = evaluation.pop("relations")
    answer_set = evaluation.pop("answer_set")
    (output / "relations.json").write_text(json.dumps(output_relations, indent=2) + "\n")
    answer_atoms = [atom for atom in answer_set if atom.startswith(("result(", "violation(", "counterexample("))]
    (output / "answers.lp").write_text("% Exact shown result atoms; use report.json for SAT/UNSAT query outcomes.\n" + "\n".join(answer_atoms) + "\n")
    (output / "answer_set.lp").write_text("% All shown atoms of the unique base stable model.\n" + "\n".join(answer_set) + "\n")
    sources = [*MODEL.glob("*.lp"), MODEL / "coverage.json", Path(__file__), ROOT / "scripts/import_msc_snapshot.py",
               ROOT / "scripts/run_msc_datalog.py", ROOT / "asp/requirements.txt"]
    report = {"completed": True, "mutation": mutation, "all_checks_passed": all(c["status"] == "pass" for c in evaluation["checks"]),
              "coverage_scope": "original 46-theorem baseline; later Lean extensions are not checked here",
              "unmapped_lean_theorems": unmapped_lean_theorems(),
              "engine": "clingo " + clingo.__version__, "evidence": evidence,
              "proof_kind": "trusted stable-model solving; no independent UNSAT certificate checker or Lean proof term",
              "input_sha256": {name: sha(output / name) for name in ["facts.lp", "packet_cases.lp"]},
              "source_sha256": {str(path.relative_to(ROOT)): sha(path) for path in sorted(sources)}, **evaluation}
    report["timing_seconds"]["validate_and_export"] = import_seconds
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--checks", type=Path, default=DEFAULT_CHECKS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mutation", choices=MUTATIONS)
    parser.add_argument("--timeout", type=float, default=60, help="timeout per solve, in seconds; excludes grounding")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    output = args.output
    if output is None and args.mutation:
        output = ROOT / "artifacts/msc-asp-experiments" / args.mutation
    report = run_model(args.snapshot, args.checks, output, args.mutation, args.timeout)
    failed = [c for c in report["checks"] if c["status"] != "pass"]
    print(f"{len(report['checks']) - len(failed)}/{len(report['checks'])} ASP checks passed; {len(failed)} SAT counterexample queries.")
    print(json.dumps(report["statistics"], sort_keys=True))
    for item in failed:
        print(item["name"], json.dumps(item["witnesses"]))
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
