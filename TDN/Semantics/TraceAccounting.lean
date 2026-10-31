import Cslib.Foundations.Semantics.LTS.Basic
import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.TraceAccounting

/-- Local resource accounting composes over CSLib traces. Credit and debit are event counts,
not physical time. The result is independent of the concrete transition system. -/
theorem trace_balance {State Action : Type} (system : Cslib.LTS State Action)
    (measure : State → Nat) (credit debit : Action → Nat)
    (stepBalance : ∀ before action after, system.Tr before action after →
      measure after + debit action = measure before + credit action)
    {before after : State} {actions : List Action}
    (run : system.MTr before actions after) :
    measure after + (actions.map debit).sum = measure before + (actions.map credit).sum := by
  induction run with
  | refl => simp
  | stepL step rest ih =>
    have one := stepBalance _ _ _ step
    simp only [List.map_cons, List.sum_cons]
    omega

theorem increase_requires_credit {State Action : Type} (system : Cslib.LTS State Action)
    (measure : State → Nat) (credit debit : Action → Nat)
    (stepBalance : ∀ before action after, system.Tr before action after →
      measure after + debit action = measure before + credit action)
    {before after : State} {actions : List Action}
    (run : system.MTr before actions after) :
    measure after - measure before ≤ (actions.map credit).sum := by
  have balanced := trace_balance system measure credit debit stepBalance run
  omega

end TDN.TraceAccounting
