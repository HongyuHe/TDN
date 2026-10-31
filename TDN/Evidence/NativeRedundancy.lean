import TDN.Evidence.SupplementalTypes

namespace TDN.Imported.NativeRedundancy

def probes : List Evidence.MechanismProbe := [⟨"primary-1", "delivered", "delivered", 3, 3⟩, ⟨"primary-2", "delivered", "delivered", 3, 3⟩, ⟨"primary-3", "delivered", "delivered", 3, 3⟩, ⟨"primary-4", "delivered", "delivered", 3, 3⟩, ⟨"active-sharing-1", "delivered", "delivered", 3, 3⟩, ⟨"active-sharing-2", "delivered", "delivered", 3, 3⟩, ⟨"active-sharing-3", "delivered", "delivered", 3, 3⟩, ⟨"active-sharing-4", "delivered", "delivered", 3, 3⟩, ⟨"primary-outage-1", "no_reply", "no_reply", 3, 0⟩, ⟨"standby-restored-1", "delivered", "delivered", 3, 3⟩, ⟨"standby-restored-2", "delivered", "delivered", 3, 3⟩, ⟨"standby-restored-3", "delivered", "delivered", 3, 3⟩, ⟨"standby-restored-4", "delivered", "delivered", 3, 3⟩, ⟨"original-restored-1", "delivered", "delivered", 3, 3⟩, ⟨"original-restored-2", "delivered", "delivered", 3, 3⟩, ⟨"original-restored-3", "delivered", "delivered", 3, 3⟩, ⟨"original-restored-4", "delivered", "delivered", 3, 3⟩]

theorem recorded_probe_outcomes : probes ≠ [] ∧ ∀ p ∈ probes, p.expected = p.observed := by unfold probes; decide

theorem outage_and_restoration_witnesses : (∃ p ∈ probes, p.observed = "no_reply") ∧ (∃ p ∈ probes, p.id = "standby-restored-1" ∧ 0 < p.received) := by unfold probes; decide

end TDN.Imported.NativeRedundancy
