import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.Temporal

/-- A time value uses the same declared physical unit throughout an instance.
A sequence index cannot discharge an elapsed-time bound. -/
structure Event where
  time : Nat
  actor : Nat
  kind : String
  object : Nat
  deriving DecidableEq, Repr

/-- A bounded observation checks only listed events, with explicit coverage. -/
def Prior (events : List Event) (kind : String) (e : Event) : Prop :=
  ∃ witness ∈ events, witness.kind = kind ∧ witness.object = e.object ∧ witness.time < e.time

def WithinDeadline (detected reported allowance : Nat) : Prop :=
  detected ≤ reported ∧ reported ≤ detected + allowance

theorem deadline_elapsed_bound {detected reported allowance : Nat}
    (h : WithinDeadline detected reported allowance) : reported - detected ≤ allowance := by
  unfold WithinDeadline at h
  omega

end TDN.Temporal
