"""Validate the revised partial-proof register and emit a Lean dependency audit."""
import argparse
import json
from pathlib import Path
import re

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*\Z")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--register", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--root", type=Path, default=Path.cwd())
    p.add_argument("--allow-pending", action="store_true")
    a = p.parse_args()
    data = json.loads(a.register.read_text())
    rows = data["groups"]
    assert sorted(r["group_id"] for r in rows) == [f"RG-{n:03d}" for n in range(1, 77)]
    assert all(r["review_complete"] is True for r in rows), "Unreviewed group"
    allowed = {"meaningful_positive_partial", "no_positive_clause_supported_currently"}
    if a.allow_pending:
        allowed.add("practical_positive_partial_pending")
    assert all(r["classification"] in allowed for r in rows), "Practical proof work remains"
    positives = [r for r in rows if r["classification"] == "meaningful_positive_partial"]
    entries = []
    for row in positives:
        general, application = row["general"], row["application"]
        assert NAME.fullmatch(general) and NAME.fullmatch(application), "Invalid declaration reference"
        assert row.get("clause") and row.get("reason") and row.get("evidence"), "Missing clause/evidence reasoning"
        for name in row["evidence"]:
            relative = Path(name)
            assert not relative.is_absolute() and ".." not in relative.parts, "Evidence must be repository-relative"
            assert (a.root / relative).exists(), "Missing evidence: " + name
        entries.append('  (' + json.dumps(row["group_id"]) + ', ``' + general + ', ``' + application + ')')
    for row in rows:
        if row["classification"] == "no_positive_clause_supported_currently":
            assert row.get("reason"), "Unsupported group lacks explanation"
    source = '''import TDN
import Lean.Util.FoldConsts

open Lean Elab Command

/- Only proof bodies are traversed. A general theorem mentioned solely in a type
does not establish that the snapshot application uses its proof. -/
partial def followsGeneralProof (env : DataPlaneModel) (target : Name)
    (pending : List Name) (visited : NameSet := {}) : Bool :=
  match pending with
  | [] => false
  | current :: rest =>
    if current == target then true
    else if visited.contains current then followsGeneralProof env target rest visited
    else
      let used := match env.find? current with
        | some info => match info.value? (allowOpaque := true) with
          | some value => value.getUsedConstants.toList.filter fun n =>
            n.toString.startsWith "TDN." || n.toString.startsWith "_private.TDN."
          | none => []
        | none => []
      followsGeneralProof env target (used ++ rest) (visited.insert current)

run_cmd do
  let env ← getEnv
  let entries : Array (String × Name × Name) := #[
''' + ',\n'.join(entries) + ''']
  for (group, general, application) in entries do
    for name in [general, application] do
      match env.find? name with
      | some info => unless info.isTheorem do
          throwError "{group}: {name} is not a theorem"
      | none => throwError "{group}: missing declaration {name}"
    unless followsGeneralProof env general [application] do
      throwError "{group}: application {application} does not use general proof {general}"
  logInfo m!"Verified {entries.size} requirement-group applications use their recorded general proofs."
'''
    a.output.write_text(source)
    print(json.dumps({"groups_reviewed": 76, "positive_partials": len(positives),
                      "unsupported_currently": sum(r["classification"] == "no_positive_clause_supported_currently" for r in rows),
                      "pending": sum(r["classification"] == "practical_positive_partial_pending" for r in rows),
                      "final_completion_check": not a.allow_pending,
                      "scope": "Source-clause meaning and observed implementation correspondence require independent review."}))


if __name__ == "__main__":
    main()
