import Mathlib.Data.List.Basic

namespace TDN.Targets

structure UnusedInterfaceState where
  identity : String
  enabled : Bool
  deriving DecidableEq, Repr

/-- The inventory contains actual interfaces independently identified as unused.
An empty active subset establishes PF2 for that selected inventory. -/
theorem unused_interfaces_disabled_from_empty_active_subset
    (unused : List UnusedInterfaceState)
    (checked : unused.filter (fun interface => interface.enabled) = []) :
    ∀ interface ∈ unused, interface.enabled = false := by
  intro interface member
  cases active : interface.enabled with
  | false => rfl
  | true =>
    have present : interface ∈ unused.filter (fun item => item.enabled) :=
      List.mem_filter.mpr ⟨member, active⟩
    rw [checked] at present
    exact False.elim (List.not_mem_nil present)

end TDN.Targets
