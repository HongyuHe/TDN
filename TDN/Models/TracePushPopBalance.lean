import Cslib.Foundations.Semantics.LTS.Basic
import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.TracePushPopBalance

theorem trace_balance {State Action : Type} (system : Cslib.LTS State Action)
    (measure : State → Nat) (pushes pops : Action → Nat)
    (stepBalance : ∀ before action after, system.Tr before action after →
      measure after + pops action = measure before + pushes action)
    {before after : State} {actions : List Action}
    (run : system.MTr before actions after) :
    measure after + (actions.map pops).sum = measure before + (actions.map pushes).sum := by
  induction run with
  | refl => simp
  | stepL step rest ih =>
    have one := stepBalance _ _ _ step
    simp only [List.map_cons, List.sum_cons]
    omega

theorem increase_requires_pushes {State Action : Type} (system : Cslib.LTS State Action)
    (measure : State → Nat) (pushes pops : Action → Nat)
    (stepBalance : ∀ before action after, system.Tr before action after →
      measure after + pops action = measure before + pushes action)
    {before after : State} {actions : List Action}
    (run : system.MTr before actions after) :
    measure after - measure before ≤ (actions.map pushes).sum := by
  have balanced := trace_balance system measure pushes pops stepBalance run
  omega

end TDN.TracePushPopBalance
