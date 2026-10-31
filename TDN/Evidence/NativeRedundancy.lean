import TDN.Import.Command
import TDN.Evidence.SupplementalTypes

namespace TDN.Imported.NativeRedundancy

tdn_data probes : List Evidence.MechanismProbe from "../../evidence/lean/NativeRedundancy.json" ["TDN.Imported.NativeRedundancy.probes"]

theorem recorded_probe_outcomes : probes ≠ [] ∧ ∀ p ∈ probes, p.expected = p.observed := by unfold probes; decide

theorem outage_and_restoration_witnesses : (∃ p ∈ probes, p.observed = "no_reply") ∧ (∃ p ∈ probes, p.id = "standby-restored-1" ∧ 0 < p.received) := by unfold probes; decide

end TDN.Imported.NativeRedundancy
