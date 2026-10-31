import TDN.Import.Command
import TDN.Evidence.DomainTypes

namespace TDN.Imported.NativeSharedBinding

set_option maxRecDepth 100000

tdn_data peerLevels : List (SecurityLevel × SecurityLevel) from "../../evidence/lean/NativeSharedBinding.json" ["TDN.Imported.NativeSharedBinding.peerLevels"]

theorem observed_inner_peers_have_same_full_declared_level : peerLevels ≠ [] ∧ ∀ p ∈ peerLevels, p.1 = p.2 := by unfold peerLevels; decide

tdn_data capturedLevels : List SecurityLevel from "../../evidence/lean/NativeSharedBinding.json" ["TDN.Imported.NativeSharedBinding.capturedLevels"]

theorem captured_source_figure_six_levels : Evidence.HasSourceFigureSixLevels capturedLevels := by unfold Evidence.HasSourceFigureSixLevels capturedLevels; decide

tdn_data logicalProbes : List (String × String × String) from "../../evidence/lean/NativeSharedBinding.json" ["TDN.Imported.NativeSharedBinding.logicalProbes"]

theorem recorded_logical_domain_outcomes : ∀ p ∈ logicalProbes, p.2.2 = (if p.1 = p.2.1 then "delivered" else "no_reply") := by unfold logicalProbes; decide

theorem positive_and_negative_witnesses : (∃ p ∈ logicalProbes, p.2.2 = "delivered") ∧ (∃ p ∈ logicalProbes, p.1 ≠ p.2.1 ∧ p.2.2 = "no_reply") := by unfold logicalProbes; decide

end TDN.Imported.NativeSharedBinding
