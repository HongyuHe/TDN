import TDN.Import.NativeDecide
import Lean.Elab.Command
import Lean.Util.CollectAxioms

open Lean Elab Command

namespace NativeCheckTests

def independent (_parameter : Nat) : List Nat := [1, 2, 3]

theorem concrete_check : (List.range 1000).length = 1000 := by native_decide

example (parameter : Nat) : independent parameter = [1, 2, 3] := by
  unfold_check_parameters
  native_decide

example (parameter : Nat) : parameter = parameter := by
  fail_if_success unfold_check_parameters
  rfl

example (parameter : Nat) : independent parameter = [1, 2, 3] := by
  close_check_with (0 : Nat)
  native_decide

example (parameter : Nat) : parameter = parameter := by
  fail_if_success close_check_with (0 : Nat)
  rfl

example : True := by
  fail_if_success have : 1 = 2 := by native_decide
  trivial

axiom unauthorized : True
axiom forged._native.native_decide.ax_1 : decide False = true
axiom wrongShape._native.native_decide.ax_1 : True
axiom falseEvidence : False

local instance untrustedDecision : Decidable False := .isTrue falseEvidence

theorem decision_with_untrusted_premise : False := by
  native_decide

run_cmd do
  let axioms ← collectAxioms ``concrete_check
  unless axioms.size == 1 do throwError "Expected one native evaluation axiom"
  unless ← liftTermElabM <| TDN.ProofTrust.verifyNativeDecision axioms[0]! do
    throwError "The audit rejected a genuine successful native check"
  for name in #[``unauthorized, ``forged._native.native_decide.ax_1,
      ``wrongShape._native.native_decide.ax_1] do
    if ← liftTermElabM <| TDN.ProofTrust.verifyNativeDecision name then
      throwError "The audit accepted a forbidden axiom: {name}"
  let dependencies ← collectAxioms ``decision_with_untrusted_premise
  unless dependencies.contains ``falseEvidence do
    throwError "Native evaluation concealed an untrusted premise"
  if ← liftTermElabM <| TDN.ProofTrust.verifyNativeDecision ``falseEvidence then
    throwError "The audit accepted an untrusted premise"

end NativeCheckTests
