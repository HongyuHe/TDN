import TDN.Import.Command
import TDN.Evidence.SupplementalTypes

import TDN.Semantics.BridgePolicy

namespace TDN.Imported.Extensions

set_option maxRecDepth 100000

def httpChain0 := BridgePolicy.chain 168493057 168558594

theorem http_exception_0_bounded (p : BridgePolicy.Frame) (h4 : p.etherType = 2048) (ht : p.ipProtocol = 6) (ha : Filter.evaluate httpChain0 .deny p = .allow) : BridgePolicy.HTTPRequest 168493057 168558594 p ∨ BridgePolicy.HTTPResponse 168493057 168558594 p := BridgePolicy.accepted_tcp_is_bounded _ _ p h4 ht ha

def httpChain1 := BridgePolicy.chain 168493057 168558594

theorem http_exception_1_bounded (p : BridgePolicy.Frame) (h4 : p.etherType = 2048) (ht : p.ipProtocol = 6) (ha : Filter.evaluate httpChain1 .deny p = .allow) : BridgePolicy.HTTPRequest 168493057 168558594 p ∨ BridgePolicy.HTTPResponse 168493057 168558594 p := BridgePolicy.accepted_tcp_is_bounded _ _ p h4 ht ha

tdn_data revocationStatuses : List (String × List String) from "../../evidence/lean/Extensions.json" ["TDN.Imported.Extensions.revocationStatuses"]

theorem observed_revocation_status_pairs : revocationStatuses ≠ [] ∧ ∀ c ∈ revocationStatuses, c.2 = ["good","revoked"] := by unfold revocationStatuses; decide

tdn_data eapResults : List (String × String × Bool × String) from "../../evidence/lean/Extensions.json" ["TDN.Imported.Extensions.eapResults"]

theorem eap_authentication_without_successful_data_probe : eapResults ≠ [] ∧ ∀ e ∈ eapResults, e.2.1 = "TLSv1.2" ∧ e.2.2.1 = true ∧ e.2.2.2 ∈ ["not_attempted","runtime_error"] := by unfold eapResults; decide

tdn_data awSamples : List Evidence.TLSSample from "../../evidence/lean/Extensions.json" ["TDN.Imported.Extensions.awSamples"]

theorem recorded_host_and_guest_tls_use : Evidence.TLSRecordedOutcomes awSamples := by unfold Evidence.TLSRecordedOutcomes awSamples; decide

tdn_data redundancyProbes : List Evidence.MechanismProbe from "../../evidence/lean/Extensions.json" ["TDN.Imported.Extensions.redundancyProbes"]

theorem recorded_manual_redundancy_probe_outcomes : redundancyProbes ≠ [] ∧ ∀ p ∈ redundancyProbes, p.expected = p.observed := by unfold redundancyProbes; decide

theorem outage_and_restoration_witnesses : (∃ p ∈ redundancyProbes, p.observed = "no_reply") ∧ (∃ p ∈ redundancyProbes, p.id = "standby-restored-1" ∧ 0 < p.received) := by unfold redundancyProbes; decide

end TDN.Imported.Extensions
