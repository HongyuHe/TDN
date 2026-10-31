import TDN.Targets.Components

namespace TDN.Tests
open Targets

def eitherService (allowed : Set Bool) : Prop := false ∈ allowed ∨ true ∈ allowed

lemma singleton_service_is_minimal (chosen : Bool) : Minimal eitherService {chosen} := by
  refine ⟨?_, ?_⟩
  · cases chosen <;> simp [eitherService]
  · intro alternative feasible subset value member
    have equal : value = chosen := member
    subst value
    rcases feasible with first | second
    · have same : false = chosen := subset first
      simpa [← same] using first
    · have same : true = chosen := subset second
      simpa [← same] using second

example : Minimal eitherService ({false} : Set Bool) ∧
    Minimal eitherService ({true} : Set Bool) :=
  ⟨singleton_service_is_minimal false, singleton_service_is_minimal true⟩

example : ¬ (({false} : Set Bool) ⊆ {true}) := by simp

example : ¬ Minimal eitherService (∅ : Set Bool) := by
  intro minimal
  simpa [eitherService] using minimal.1

end TDN.Tests
