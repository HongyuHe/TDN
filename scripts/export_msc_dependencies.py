#!/usr/bin/env python3
"""Export direct dependencies from the compiled required network theory."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    targets, source_hashes = {}, {}
    for directory in [ROOT / "TDN/MSC", ROOT / "TDN/Network"]:
        for path in sorted(directory.glob("*.lean")):
            if path.name in {"HistoricalDeployment.lean", "SnapshotDiagnostics.lean"}:
                continue
            source = path.read_text()
            namespace = re.search(r"^namespace ([\w.]+)$", source, re.M)
            if namespace is None:
                continue
            relative = str(path.relative_to(ROOT))
            source_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            for match in re.finditer(r"^(def|abbrev|structure|inductive|theorem) ([\w.?]+)", source, re.M):
                name = namespace[1] + "." + match[2]
                if name in targets:
                    raise ValueError(f"duplicate declaration: {name}")
                targets[name] = {"source": relative, "line": source[:match.start()].count("\n") + 1,
                                 "kind": match[1]}
    names = sorted(targets)
    source = "import Lean\nimport TDN\nopen Lean Elab Command\nrun_cmd do\n"
    source += "  let env ← getEnv\n  let names : Array Name := #[" + ", ".join("`" + n for n in names) + "]\n"
    source += '''  for name in names do
    let some info := env.find? name | throwError "Missing declaration {name}"
    let typeDeps := info.type.getUsedConstants.map Name.toString
    let valueDeps := match info.value? (allowOpaque := true) with
      | some value => value.getUsedConstants.map Name.toString
      | none => #[]
    logInfo (Json.mkObj [("name", toJson name.toString),
      ("type_dependencies", toJson typeDeps), ("value_dependencies", toJson valueDeps)]).compress
'''
    script = output / "Dependencies.lean"
    script.write_text(source)
    lake = shutil.which("lake") or str(Path.home() / ".elan/bin/lake")
    result = subprocess.run([lake, "env", "lean", str(script)], cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    (output / "dependency-export.log").write_text(result.stdout)
    if result.returncode:
        raise SystemExit(result.stdout)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{"name":')]
    if sorted(row["name"] for row in rows) != names:
        raise ValueError("compiled dependency export omitted or duplicated declarations")
    (output / "dependencies.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    edges = []
    for row in rows:
        for kind in ["type_dependencies", "value_dependencies"]:
            for target in row[kind]:
                if target in targets:
                    edges.append({"from": row["name"], "to": target, "kind": kind})
    graph = {"nodes": names, "edges": edges, "declarations": targets,
             "source_sha256": source_hashes,
             "method": "Lean compiled declaration types and proof/definition values; direct constants only"}
    (output / "dependency-graph.json").write_text(json.dumps(graph, indent=2) + "\n")
    print(f"Exported {len(names)} declarations and {len(edges)} direct named dependency edges.")


if __name__ == "__main__":
    main()
