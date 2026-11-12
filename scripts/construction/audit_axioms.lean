import TDN
import TDN.Import.NativeDecide
import Lean.Util.CollectAxioms

set_option maxHeartbeats 20000000
set_option maxRecDepth 100000

open Lean Elab Command

/- Run after `lake build` with `lake env lean scripts/construction/audit_axioms.lean`.
The output lists the transitive axioms of imported theorems in the TDN namespace,
including private declarations whose generated names identify a TDN module. The check rejects
anything outside Lean's three standard logical axioms and closed native_decide results.
Every accepted native result is evaluated again under the compiler trust policy;
source interpretation and the truth of imported observations require separate review. -/
run_cmd do
  let environment ← getEnv
  let declarations := environment.constants.toList.filterMap fun (name, information) =>
    if (name.toString.startsWith "TDN." || name.toString.startsWith "_private.TDN.") &&
        information.isTheorem then some name else none
  let names := declarations.toArray.qsort (fun a b => a.toString < b.toString)
  let allowed := TDN.ProofTrust.foundationalAxioms
  let mut nativeChecks : NameSet := {}
  let mut rejected : NameSet := {}
  let mut failures : Array Name := #[]
  for name in names do
    let axioms ← collectAxioms name
    let record := Json.mkObj [
      ("declaration", toJson name.toString),
      ("axioms", toJson (axioms.map Name.toString))]
    logInfo m!"{record.compress}"
    for axiomName in axioms do
      if allowed.contains axiomName || nativeChecks.contains axiomName || rejected.contains axiomName then
        continue
      if ← liftTermElabM <| TDN.ProofTrust.verifyNativeDecision axiomName then
        nativeChecks := nativeChecks.insert axiomName
      else
        rejected := rejected.insert axiomName
    if axioms.any rejected.contains then
      failures := failures.push name
  if names.isEmpty then
    throwError "The audit found no imported TDN theorems."
  if !failures.isEmpty then
    throwError "Unexpected axioms in {failures.map Name.toString}"
  logInfo m!"Checked {names.size} imported TDN namespace/module theorem declarations; re-evaluated {nativeChecks.size} native_decide results."
