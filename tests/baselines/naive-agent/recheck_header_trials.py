"""Rerun the eight benchmark checks on the saved clean and protocol-253 snapshots."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from delivery_paths import check_trial as check_delivery
from full_suite import ROOT, suite
from measure import typecheck
from observe_controls import HERE, NETWORKS
from score_trials import CHECK_DIRECTORIES, HEADER_RECHECK, read


FAMILY = "inner-empty-ipv4-header"
PROOF_FILES = ["ModeChecks.lean", "AttachmentChecks.lean", "TopologyChecks.lean",
               "SnapshotCompliance.lean", "HeaderCompliance.lean", "FirewallChecks.lean",
               "DeliveryPathChecks.lean", "GrayConnectivityChecks.lean"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot_digest(folder):
    combined = hashlib.sha256()
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        combined.update(str(path.relative_to(folder)).encode() + b"\0" + bytes.fromhex(digest(path)))
    return combined.hexdigest()


def imports(path):
    return re.findall(r"^(?:public\s+)?import\s+(TDN\.[\w.]+)", path.read_text(), re.M)


def with_recorded_sources(run, sources, destination):
    frozen = read(run / "protocol.json")["working_tree_files_sha256"]
    with TemporaryDirectory(prefix="tdn-header-proofs-") as work:
        project = Path(work)
        for name, expected in frozen.items():
            if not (name.startswith("TDN/") or name in ("lean-toolchain", "lake-manifest.json", "specs/requirement_clause_map.json")):
                continue
            source = next((p for p in (sources / name, ROOT / name) if p.is_file() and digest(p) == expected), None)
            if source is None:
                raise ValueError(f"Supply the recorded version of {name} from the benchmark")
            target = project / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        shutil.copyfile(ROOT / "lakefile.toml", project / "lakefile.toml")
        shutil.copyfile(sources / "TDN.lean" if (sources / "TDN.lean").is_file() else ROOT / "TDN.lean", project / "TDN.lean")
        (project / ".lake").mkdir()
        (project / ".lake/packages").symlink_to(ROOT / ".lake/packages", target_is_directory=True)
        (project / "data").symlink_to(ROOT / "data", target_is_directory=True)
        shutil.copytree(ROOT / "mcp/tdn_evidence", project / "mcp/tdn_evidence",
                        ignore=shutil.ignore_patterns("__pycache__"))
        bench = project / HERE.relative_to(ROOT)
        bench.mkdir(parents=True)
        for original in [*HERE.glob("*.py"), *HERE.glob("*.lean"), HERE / "clause_scope.json", HERE / "clause_branches.json"]:
            shutil.copyfile(original, bench / original.name)
        for directory in ("profiles", "perimeter"):
            (bench / directory).symlink_to(HERE / directory, target_is_directory=True)
        modules = sorted({module for file in PROOF_FILES for module in imports(bench / file)})
        subprocess.run(["lake", "build", *modules], cwd=project, check=True)
        subprocess.run([sys.executable, str(bench / Path(__file__).name), str(run), "--out", str(destination)],
                       cwd=project, check=True)


def run_suite(run, output, network, phase, frozen):
    clean = phase == "controls"
    trial = run / "trials" / FAMILY / network
    captured = run / "raw" / ("controls" if clean else Path("trials") / FAMILY) / network
    if not read(captured / "capture.json")["converged"]:
        raise ValueError(f"Unsettled snapshot for {network} {phase}")
    snapshot = captured / "snapshot"
    suite(snapshot / "native", snapshot / "processing", output / "tdn-full")
    for name, suffix in (("modes", "modes"), ("attachments", "attachments"), ("gray connectivity", "gray-paths")):
        original = run / "controls" / f"{network}-{suffix}" if clean else trial / CHECK_DIRECTORIES[name]
        source, = original.glob("*.lean")
        data = read(original / "evidence.json")
        result = typecheck(source, output / CHECK_DIRECTORIES[name], data, set(source.read_text().splitlines()))
        if result["evidence_sha256"] != read(original / "result.json")["evidence_sha256"]:
            raise ValueError(f"The saved {name} input changed for {network} {phase}")
    check_delivery(run, network, output)
    results = {name: read(output / folder / "result.json") for name, folder in CHECK_DIRECTORIES.items()}
    for name, result in results.items():
        if result["source_sha256"] != frozen[name]["source_sha256"]:
            raise ValueError(f"The archived {name} proof program changed for {network} {phase}")
        if result["status"] not in ("pass", "rejected") or result["typecheck_ns"] is None:
            raise ValueError(f"Incomplete {name} check on {network} {phase}: {result['status']}")
        if clean and (result["status"] != "pass" or result["evidence_sha256"] != frozen[name]["evidence_sha256"]):
            raise ValueError(f"The {name} clean control differs for {network}")
    retained = read(output / "tdn-full/headers/evidence.json")
    target = read(trial / "adjudication.json")["target"]
    rules = retained["devices"][retained["deviceIds"][target]]["inputRules"]
    indices = [i for i, rule in enumerate(rules) if rule["verdict"] == "allow"
               and {"protocol": {"name": "253"}} in rule["atoms"]]
    if (clean and indices) or (not clean and len(indices) != 1):
        raise ValueError(f"The Lean input does not match the recorded protocol change on {network} {phase}")
    return {
        "snapshot": str(snapshot.relative_to(run)), "snapshot_sha256": snapshot_digest(snapshot),
        "target": target, "protocol_253_input_rule_indices": indices,
        "checks": {name: result["status"] for name, result in results.items()},
        "failed_header_obligations": results["headers"]["failed_obligations"],
        "typecheck_ns": sum(result["typecheck_ns"] for result in results.values()),
    }


def recheck(run, destination):
    if destination.exists():
        raise FileExistsError(f"Rerun already recorded at {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    protocol = read(run / "protocol.json")
    for name, expected in protocol["working_tree_files_sha256"].items():
        if name.startswith("TDN/") and (not (ROOT / name).is_file() or digest(ROOT / name) != expected):
            raise ValueError(f"{name} differs from the benchmark. Use --theory-sources to build the recorded version.")
    delivery = read(run / "delivery-protocol.json")["clean_proofs"]
    gray = read(run / "gray-connectivity-protocol.json")["clean_proofs"]
    parser_files = ["mcp/tdn_evidence/parsers/native_nft.py", "mcp/tdn_evidence/parsers/packet_policy.py"]
    record = {
        "started_at": datetime.now(timezone.utc).isoformat(), "family": FAMILY,
        "timing": "Sum of the eight intervals measured inside Lean after evidence import. The rerun used the archived snapshots.",
        "lean_version": subprocess.check_output(["lake", "env", "lean", "--version"], cwd=ROOT, text=True).strip(),
        "parser_files": {name: {"original": protocol["working_tree_files_sha256"][name], "rerun": digest(ROOT / name)}
                         for name in parser_files},
        "networks": {},
    }
    with TemporaryDirectory(dir=destination.parent, prefix="header-recheck-") as work:
        staged = Path(work) / "results"
        for network in NETWORKS:
            frozen = {**protocol["clean_proofs"][network], "delivery": delivery[network], "gray connectivity": gray[network]}
            cases = {}
            for phase in ("controls", "trials"):
                target = staged / phase / network
                target.mkdir(parents=True)
                cases[phase] = run_suite(run, target, network, phase, frozen)
                print(network, phase, cases[phase]["checks"], flush=True)
            faulty = cases["trials"]
            if faulty["checks"]["headers"] == "rejected" and any(
                line.startswith("lemma protocol_rules_checked ") for line in faulty["failed_header_obligations"]
            ):
                verdict = "hit"
                reason = ("The repaired importer retained the rule allowing protocol 253. Lean rejected "
                          "protocol_rules_checked on the faulty snapshot. The identical proof passed on its clean control.")
            elif all(status == "pass" for status in faulty["checks"].values()):
                verdict, reason = "miss", "All eight checks passed on the faulty snapshot."
            else:
                raise ValueError(f"The Lean failure needs manual attribution on {network}")
            record["networks"][network] = {**cases, "verdict": verdict, "reason": reason}
        dependency_file = staged / "lean-dependencies.json"
        sources = [p for p in (staged / "controls" / NETWORKS[0]).rglob("*.lean")]
        pending = list(sources)
        dependencies = {}
        while pending:
            source = pending.pop()
            for module in imports(source):
                if module in dependencies:
                    continue
                relative = module.replace(".", "/")
                path = ROOT / (relative + ".lean")
                dependencies[module] = {
                    "source_sha256": digest(path),
                    "original_source_sha256": protocol["working_tree_files_sha256"].get(relative + ".lean"),
                    "olean_sha256": digest(ROOT / ".lake/build/lib/lean" / (relative + ".olean")),
                }
                pending.append(path)
        dependency_file.write_text(json.dumps(dependencies, indent=2, sort_keys=True) + "\n")
        with tarfile.open(staged / "lean-sources.tar.gz", "w:gz") as archive:
            for name in sorted(protocol["working_tree_files_sha256"]):
                if name.startswith("TDN/") or name in ("lean-toolchain", "lake-manifest.json", "specs/requirement_clause_map.json"):
                    archive.add(ROOT / name, arcname=name)
            for name in ("TDN.lean", "lakefile.toml"):
                archive.add(ROOT / name, arcname=name)
        record["finished_at"] = datetime.now(timezone.utc).isoformat()
        (staged / "record.json").write_text(json.dumps(record, indent=2) + "\n")
        staged.rename(destination)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--theory-sources", type=Path, help="Original source tree, or an extracted lean-sources.tar.gz")
    parser.add_argument("--out", type=Path, help="New directory for an independent repeat")
    args = parser.parse_args()
    run = args.run.resolve()
    destination = args.out.resolve() if args.out else run / HEADER_RECHECK
    if args.theory_sources:
        with_recorded_sources(run, args.theory_sources.resolve(), destination)
    else:
        print(recheck(run, destination))
