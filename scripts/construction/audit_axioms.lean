import TDN
import Lean.Util.CollectAxioms

open Lean Elab Command

/- Run after `lake build` with `lake env lean scripts/construction/audit_axioms.lean`.
The output lists the transitive axioms of imported theorems in the TDN namespace,
including private declarations whose generated names identify a TDN module. The check rejects
anything outside Lean's three standard logical axioms. The audit checks proof dependencies;
source interpretation and the truth of imported observations require separate review. -/
run_cmd do
  let environment ← getEnv
  let declarations := environment.constants.toList.filterMap fun (name, information) =>
    if (name.toString.startsWith "TDN." || name.toString.startsWith "_private.TDN.") &&
        information.isTheorem then some name else none
  let names := declarations.toArray.qsort (fun a b => a.toString < b.toString)
  let allowed := #[``propext, ``Classical.choice, ``Quot.sound]
  let mut failures : Array Name := #[]
  for name in names do
    let axioms ← collectAxioms name
    let record := Json.mkObj [
      ("declaration", toJson name.toString),
      ("axioms", toJson (axioms.map Name.toString))]
    logInfo m!"{record.compress}"
    if axioms.any (fun axiomName => !allowed.contains axiomName) then
      failures := failures.push name
  if names.isEmpty then
    throwError "The audit found no imported TDN theorems."
  if !failures.isEmpty then
    throwError "Unexpected axioms in {failures.map Name.toString}"
  logInfo m!"Checked {names.size} imported TDN namespace/module theorem declarations."
