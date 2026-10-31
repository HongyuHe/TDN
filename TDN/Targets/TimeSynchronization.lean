import TDN.Targets.Operations
import TDN.Semantics.ClockSamples

namespace TDN.Targets

/-- Each relevant component is assigned a particular time source. These checks are
local to that assignment. The caller must supply source trust and actual synchronization;
an NTP response or a configured address alone does not provide either fact. -/
theorem trusted_time_from_component_assignments {C S : Type}
    (model : TimeSynchronizationModel C S) (assigned : C → S)
    (red : ∀ c ∈ model.components, model.inner c ∨ model.redManagementService c →
      model.locatedIn (assigned c) .red)
    (gray : ∀ c ∈ model.components,
      model.outer c ∨ model.grayManagementService c ∨ model.grayFirewall c →
        model.locatedIn (assigned c) .grayManagement)
    (trust : ∀ c ∈ model.components,
      model.inner c ∨ model.redManagementService c ∨ model.outer c ∨
        model.grayManagementService c ∨ model.grayFirewall c → model.trusted (assigned c))
    (synchronized : ∀ c ∈ model.components,
      model.inner c ∨ model.redManagementService c ∨ model.outer c ∨
        model.grayManagementService c ∨ model.grayFirewall c →
          model.synchronizedTo c (assigned c)) :
    msc_trusted_time_synchronization model := by
  constructor
  · intro c member relevant
    have required : model.inner c ∨ model.redManagementService c ∨ model.outer c ∨
        model.grayManagementService c ∨ model.grayFirewall c := by
      rcases relevant with inner | service
      · exact Or.inl inner
      · exact Or.inr (Or.inl service)
    exact ⟨assigned c, red c member relevant, trust c member required,
      synchronized c member required⟩
  · intro c member relevant
    have required : model.inner c ∨ model.redManagementService c ∨ model.outer c ∨
        model.grayManagementService c ∨ model.grayFirewall c := Or.inr (Or.inr relevant)
    exact ⟨assigned c, gray c member relevant, trust c member required,
      synchronized c member required⟩

/-- Collected corrections provide the technical measurement contribution to RG-042.
Source approval, required management-network placement and continuous synchronization
are separate conditions in the encompassing specification above. -/
theorem all_checked_clock_corrections_improve_offset (records : List ClockSamples.Correction)
    (toleranceUs : Nat)
    (checks : ∀ r ∈ records, ClockSamples.CorrectedAtSample toleranceUs r)
    (displaced : ∀ r ∈ records, toleranceUs < r.beforeOffsetUs.natAbs) :
    ∀ r ∈ records, r.afterOffsetUs.natAbs < r.beforeOffsetUs.natAbs := by
  intro r member
  exact ClockSamples.successful_sample_improves_displaced_clock
    (checks r member) (displaced r member)

end TDN.Targets
