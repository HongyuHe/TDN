import TDN.Import.Command
import TDN.Evidence.MechanismTypes

namespace TDN.Imported.Mechanisms

set_option maxRecDepth 100000

set_option maxHeartbeats 0

tdn_data cases : List Evidence.MechanismCase from "../../evidence/lean/Mechanisms.json" ["TDN.Imported.Mechanisms.cases"]

theorem recorded_probe_expectations : Evidence.ExpectedProbeOutcomes cases := by unfold Evidence.ExpectedProbeOutcomes cases; decide

theorem each_case_has_positive_traffic : Evidence.EachCaseHasUsefulTraffic cases := by unfold Evidence.EachCaseHasUsefulTraffic cases; decide

theorem all_eight_declared_family_choices : ∀ r ∈ [4,6], ∀ g ∈ [4,6], ∀ b ∈ [4,6], ∃ c ∈ cases, c.families = some (r,g,b) := by unfold cases; decide

theorem all_four_declared_layer_pairings : ∀ i ∈ ["IPsec","MACsec"], ∀ o ∈ ["IPsec","MACsec"], ∃ c ∈ cases, c.inner = i ∧ c.outer = o := by unfold cases; decide

tdn_data macsecSettings : List Evidence.MACsecChannelSetting from "../../evidence/lean/Mechanisms.json" ["TDN.Imported.Mechanisms.macsecSettings"]

theorem recorded_macsec_selected_flags : Evidence.MACsecSelectedFlags macsecSettings := by unfold Evidence.MACsecSelectedFlags macsecSettings; decide

end TDN.Imported.Mechanisms
