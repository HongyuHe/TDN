import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.Temporal

structure Event where
  time : Nat
  actor : Nat
  kind : String
  object : Nat
  deriving DecidableEq, Repr

/-- A bounded observation checks only listed events, with explicit coverage. -/
def Prior (events : List Event) (kind : String) (e : Event) : Prop :=
  ∃ witness ∈ events, witness.kind = kind ∧ witness.object = e.object ∧ witness.time < e.time

/-- Complete histories must be supplied externally, rather than inferred from no events. -/
def RekeyDiscipline (events : List Event) : Prop :=
  ∀ e ∈ events, e.kind = "ike_rekey" → Prior events "peer_reauthentication" e

def WithinDeadline (detected reported allowance : Nat) : Prop :=
  detected ≤ reported ∧ reported ≤ detected + allowance

theorem deadline_elapsed_bound {detected reported allowance : Nat}
    (h : WithinDeadline detected reported allowance) : reported - detected ≤ allowance := by
  unfold WithinDeadline at h
  omega

/-- Configured bounds alone are independent of event-ordering obligations. -/
def SALifetimeBounds (ikeSeconds espSeconds : Nat) : Prop :=
  0 < ikeSeconds ∧ ikeSeconds ≤ 86400 ∧ 0 < espSeconds ∧ espSeconds ≤ 28800

theorem lifetime_example : SALifetimeBounds 86400 28800 := by decide

end TDN.Temporal
