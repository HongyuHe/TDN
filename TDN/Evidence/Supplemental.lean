import TDN.Import.Command
import TDN.Evidence.SupplementalTypes

namespace TDN.Imported.Supplemental

set_option maxRecDepth 100000

set_option maxHeartbeats 0

tdn_data probes : List Evidence.MechanismProbe from "../../evidence/lean/Supplemental.json" ["TDN.Imported.Supplemental.probes"]

theorem recorded_probe_expectations : probes ≠ [] ∧ ∀ p ∈ probes, p.expected = p.observed := by unfold probes; decide

theorem useful_and_negative_probe_witnesses : (∃ p ∈ probes, 0 < p.received) ∧ (∃ p ∈ probes, p.observed = "no_reply") := by unfold probes; decide

tdn_data ntpReplies : List Evidence.NTPReply from "../../evidence/lean/Supplemental.json" ["TDN.Imported.Supplemental.ntpReplies"]

theorem observed_ntp_replies_without_clock_adjustment : Evidence.RecordedNTPReplies ntpReplies := by unfold Evidence.RecordedNTPReplies ntpReplies; decide

tdn_data tlsSamples : List Evidence.TLSSample from "../../evidence/lean/Supplemental.json" ["TDN.Imported.Supplemental.tlsSamples"]

theorem supplemental_tls_recorded_outcomes : Evidence.TLSRecordedOutcomes tlsSamples := by unfold Evidence.TLSRecordedOutcomes tlsSamples; decide

tdn_data caExchanges : List Evidence.CAExchange from "../../evidence/lean/Supplemental.json" ["TDN.Imported.Supplemental.caExchanges"]

theorem observed_good_crl_authentication_exchanges : Evidence.RecordedCertificateExchanges caExchanges := by unfold Evidence.RecordedCertificateExchanges caExchanges; decide

tdn_data ospfCounts : List (String × String × Nat × Nat) from "../../evidence/lean/Supplemental.json" ["TDN.Imported.Supplemental.ospfCounts"]

theorem recorded_ospf_neighbors_and_routes : ospfCounts ≠ [] ∧ ∀ s ∈ ospfCounts, 0 < s.2.2.1 ∧ 0 < s.2.2.2 := by unfold ospfCounts; decide

tdn_data relayCounts : List (Nat × Nat × Nat) from "../../evidence/lean/Supplemental.json" ["TDN.Imported.Supplemental.relayCounts"]

theorem recorded_relay_both_branches : relayCounts ≠ [] ∧ ∀ s ∈ relayCounts, 0 < s.1 ∧ 0 < s.2.1 ∧ s.2.2 = s.1 := by unfold relayCounts; decide

end TDN.Imported.Supplemental
