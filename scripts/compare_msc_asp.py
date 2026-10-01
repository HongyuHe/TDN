#!/usr/bin/env python3
"""Compare native ASP against the actual Lean definitions and Souffle model."""

import argparse
import json
from pathlib import Path
import platform
import statistics
import sys
import tempfile

import run_msc_asp as asp
import run_msc_datalog as dl
from compare_msc_models import command

ROOT = asp.ROOT


def compare(output, runs):
    output.mkdir(parents=True, exist_ok=True)
    (output / "comparison.json").write_text(json.dumps({"completed": False}) + "\n")
    command([sys.executable, str(ROOT / "scripts/import_msc_snapshot.py"), "--check"])
    setup_seconds, _ = command(["lake", "build"])
    command([sys.executable, str(ROOT / "scripts/import_msc_snapshot.py"), "--include-management", "--check"])
    command(["lake", "build", "TDN.MSC.HistoricalDeployment"])
    baseline = asp.run_model(output=output)
    if not baseline["all_checks_passed"]:
        raise RuntimeError("ASP baseline failed")
    facts = (output / "facts.lp").read_text()
    packets = (output / "packet_cases.lp").read_text()
    base_relations = json.loads((output / "relations.json").read_text())
    lean_times, dl_times, asp_times = [], [], []
    with tempfile.TemporaryDirectory(prefix="msc-asp-comparison-") as temporary:
        temp = Path(temporary)
        datalog = dl.run_model(output=temp / "datalog")
        if not datalog["all_checks_passed"]:
            raise RuntimeError("Datalog baseline failed")
        #* The temporary TSV is only the existing Lean oracle's query interface.
        #* ASP input remains native facts.lp and packet_cases.lp throughout.
        _, _, cases, _ = asp.prepare()
        query_file = temp / "lean-query-packets.tsv"
        query_file.write_text("".join("\t".join(map(str, row)) + "\n" for row in cases))
        if query_file.read_text() != (temp / "datalog/facts/QueryPacket.facts").read_text():
            raise ValueError("ASP and Datalog firewall comparison domains differ")
        oracle_seconds, oracle = command(["lake", "env", "lean", "--run", "tests/MSCDatalogOracle.lean", str(query_file)])
        expected = {}
        for line in oracle.splitlines():
            fields = line.split("\t")
            expected.setdefault(fields[0], set()).add(tuple(fields[1:]))
        comparison = {}
        for asp_name, reference_name in asp.RELATIONS.items():
            actual = {tuple(row) for row in base_relations.get(asp_name, [])}
            lean = expected.get(reference_name, set())
            datalog_rows = {tuple(row) for row in dl.read_relation(temp / "datalog/results", reference_name)}
            comparison[reference_name] = {
                "all_equal": actual == lean == datalog_rows,
                "asp_rows": len(actual), "lean_rows": len(lean), "datalog_rows": len(datalog_rows),
                "only_asp_vs_lean": sorted(actual - lean), "only_lean_vs_asp": sorted(lean - actual),
                "only_asp_vs_datalog": sorted(actual - datalog_rows), "only_datalog_vs_asp": sorted(datalog_rows - actual)}
        for _ in range(runs):
            total = 0
            for name in ["Types", "Deployment", "Topology", "Policy", "Flow"]:
                elapsed, _ = command(["lake", "env", "lean", f"TDN/MSC/{name}.lean"])
                total += elapsed
            lean_times.append(total)
            elapsed, _ = dl.evaluate(temp / "datalog/facts", temp / "datalog-benchmark")
            dl_times.append(elapsed)
            asp_times.append(asp.evaluate(facts, packets)["timing_seconds"])
        experiments = {}
        for mutation in asp.MUTATIONS:
            trial = asp.run_model(output=output / "experiments" / mutation, mutation=mutation)
            reference = dl.run_model(output=temp / mutation, mutation=mutation)
            failures = sorted(c["name"] for c in trial["checks"] if c["status"] == "fail")
            wanted = sorted(c["name"] for c in reference["checks"] if c["status"] == "fail")
            if not failures or failures != wanted:
                raise ValueError(f"negative experiment disagreement: {mutation}: {failures} versus {wanted}")
            experiments[mutation] = {"failed_checks": failures, "matches_datalog": True,
                                     "sat_witnesses": {c["name"]: c["witnesses"] for c in trial["checks"] if c["status"] == "fail"}}
    sources = [*sorted((ROOT / "TDN/MSC").glob("*.lean")), Path(__file__), ROOT / "tests/MSCDatalogOracle.lean"]
    report = {"completed": True, "all_equal": all(row["all_equal"] for row in comparison.values()),
              "platform": platform.platform(), "lean_version": command(["lake", "env", "lean", "--version"])[1].strip(),
              "asp_engine": baseline["engine"], "datalog_engine": datalog["engine"], "runs": runs,
              "relations": comparison, "negative_experiments": experiments,
              "flow_cases": {"transmit": 16 * 512, "deliver": 16 * 512 * 512},
              "timing_seconds": {"lake_build_setup": setup_seconds, "lean_behavioral_oracle": oracle_seconds,
                  "lean_source_recheck": lean_times, "lean_source_recheck_median": statistics.median(lean_times),
                  "souffle_parse_evaluate_write": dl_times, "souffle_parse_evaluate_write_median": statistics.median(dl_times),
                  "asp_in_process": asp_times,
                  "asp_medians": {key: statistics.median(t[key] for t in asp_times) for key in asp_times[0]}},
              "timing_scope": "Warm Lean dependencies; source elaboration+tactics+kernel in five processes. Souffle parse+fixed-point+IO in one process. ASP in-process load/parse/ground, base solve, then 46 incremental counterexample queries; excludes Python startup and artifact IO. No construction-effort or kernel-only measurement; timings do not establish asymptotic complexity.",
              "evidence": baseline["evidence"],
              "source_sha256": {**baseline["source_sha256"], **datalog["source_sha256"],
                                **{str(p.relative_to(ROOT)): asp.sha(p) for p in sources}}}
    (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"all_equal": report["all_equal"], "relations": comparison,
                      "timing_seconds": report["timing_seconds"]}, indent=2))
    return report["all_equal"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/msc-node1-asp")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    raise SystemExit(0 if compare(args.output.resolve(), args.runs) else 1)


if __name__ == "__main__":
    main()
