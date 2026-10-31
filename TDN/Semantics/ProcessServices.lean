import Mathlib.Data.List.Basic

namespace TDN.ProcessServices

/-- An interpreted process inventory. Capabilities describe the actual loaded
program under the stated implementation contract, not an arbitrary desired policy. -/
structure Process (Service : Type) where
  identity : Nat
  services : List Service

def Runs {Service : Type} (processes : List (Process Service)) (service : Service) : Prop :=
  ∃ process ∈ processes, service ∈ process.services

/-- Complete process enumeration and per-program capability exclusion suffice
to exclude an active service. Enumeration completeness is a collector contract;
future process launches require a new state or a separate lifecycle argument. -/
theorem service_absent_from_process_checks {Service : Type}
    (processes : List (Process Service)) (service : Service)
    (checked : ∀ process ∈ processes, service ∉ process.services) :
    ¬ Runs processes service := by
  rintro ⟨process, member, active⟩
  exact checked process member active

end TDN.ProcessServices
