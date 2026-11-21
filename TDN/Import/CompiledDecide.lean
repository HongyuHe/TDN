import Lean.Elab.Tactic.Basic
import Lean.Meta.Transform
import Lean.Meta.Tactic.Replace
import Lean.Meta.Eval

/-! Unfold only the parts of a concrete check that mention its surrounding parameters.
Closed snapshot data remain folded. The replacement goal must be definitionally equal
to the original goal, and any remaining free parameter makes the tactic fail.
Use `unfold_check_parameters; native_decide` for a parameter-independent check.
`close_check_with` keeps custom predicates intact by substituting a closed representative,
again requiring definitional equality. The audit accepts only the foundational axioms
and closed native-decision assertions that evaluate to true when checked again. -/

open Lean Meta Elab Tactic

elab "unfold_check_parameters" : tactic => liftMetaTactic1 fun goal => goal.withContext do
  let target ← instantiateMVars (← goal.getType)
  let parameters := (← getLCtx).getFVarIds
  let mentionsParameter := fun (expression : Expr) =>
    (expression.find? fun term => term.isFVar && parameters.contains term.fvarId!).isSome
  let closed ← withTransparency .all <| Meta.transform target (pre := fun expression => do
    if !mentionsParameter expression then return .done expression
    let reduced ← whnf expression
    if reduced != expression then return .visit reduced
    return .continue)
  if closed.hasFVar then
    throwError "The check still depends on a parameter. Supply a general proof or explicit closed checks."
  goal.change closed

elab "close_check_with " value:term : tactic => do
  let representative ← Lean.Elab.Term.elabTerm value none
  let representativeType ← inferType representative
  liftMetaTactic1 fun goal => goal.withContext do
    let target ← zetaReduce (← instantiateMVars (← goal.getType))
    let mut closed := target
    for parameter in (← getLCtx).getFVarIds do
      if ← isDefEq (← inferType (mkFVar parameter)) representativeType then
        closed := closed.replaceFVar (mkFVar parameter) representative
    goal.change closed

namespace TDN.ProofTrust

def foundationalAxioms : Array Name := #[``propext, ``Classical.choice, ``Quot.sound]

def nativeDecision? (information : ConstantInfo) : Option Expr := do
  let .axiomInfo declaration := information | none
  if declaration.isUnsafe || !declaration.levelParams.isEmpty then none else do
    if (declaration.name.toString.splitOn "._native.native_decide.ax_").length != 2 then none else do
      let type := declaration.type
      if !type.isAppOfArity ``Eq 3 then none else do
        let arguments := type.getAppArgs
        if !arguments[0]!.isConstOf ``Bool || !arguments[2]!.isConstOf ``Bool.true then none else do
          let computation := arguments[1]!
          if computation.hasFVar || computation.hasMVar || !computation.isAppOfArity ``decide 2 then
            none
          else some computation

unsafe def verifyNativeDecision (name : Name) : MetaM Bool := do
  let some computation := nativeDecision? (← getConstInfo name) | return false
  evalExpr Bool (mkConst ``Bool) computation

end TDN.ProofTrust
