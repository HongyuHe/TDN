import TDN.Evidence.SupplementalTypes

namespace TDN.Imported.Supplemental

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def probes : List Evidence.MechanismProbe := [⟨"alternative-egress-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-A-B", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-B-A", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-data-path", "delivered", "delivered", 3, 3⟩, ⟨"reverse-unrouted-path", "no_reply", "no_reply", 3, 0⟩, ⟨"nested-data-path-A-B", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-B-A", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-data-path", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-A-B", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-B-A", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-data-path", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-A-B", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-B-A", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-data-path", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-A-B", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-B-A", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-data-path", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-A-B", "delivered", "delivered", 3, 3⟩, ⟨"nested-data-path-B-A", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-data-path", "delivered", "delivered", 3, 3⟩, ⟨"nested-useful-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-reverse-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-nested-traffic", "delivered", "delivered", 3, 3⟩, ⟨"red-GRE-over-nested-ESP", "delivered", "delivered", 3, 3⟩, ⟨"nested-useful-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-reverse-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-nested-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-useful-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-reverse-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-nested-traffic", "delivered", "delivered", 3, 3⟩, ⟨"red-MPLS-over-GRE-over-nested-ESP", "delivered", "delivered", 3, 3⟩, ⟨"nested-useful-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-reverse-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-nested-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-useful-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-reverse-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-nested-traffic", "delivered", "delivered", 3, 3⟩, ⟨"OSPF-learned-Red-route", "delivered", "delivered", 3, 3⟩, ⟨"nested-useful-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-reverse-traffic", "delivered", "delivered", 3, 3⟩, ⟨"nested-inner-loss", "no_reply", "no_reply", 3, 0⟩, ⟨"restored-nested-traffic", "delivered", "delivered", 3, 3⟩]

theorem recorded_probe_expectations : probes ≠ [] ∧ ∀ p ∈ probes, p.expected = p.observed := by unfold probes; decide

theorem useful_and_negative_probe_witnesses : (∃ p ∈ probes, 0 < p.received) ∧ (∃ p ∈ probes, p.observed = "no_reply") := by unfold probes; decide

def ntpReplies : List Evidence.NTPReply := [⟨"time-gray", "10.95.0.2", 123, 4, 2, true, false⟩, ⟨"time-gray", "10.95.0.2", 123, 4, 2, true, false⟩, ⟨"time-gray", "10.95.0.2", 123, 4, 2, true, false⟩, ⟨"time-red", "10.95.0.2", 123, 4, 2, true, false⟩, ⟨"time-red", "10.95.0.2", 123, 4, 2, true, false⟩, ⟨"time-red", "10.95.0.2", 123, 4, 2, true, false⟩]

theorem observed_ntp_replies_without_clock_adjustment : Evidence.RecordedNTPReplies ntpReplies := by unfold Evidence.RecordedNTPReplies ntpReplies; decide

def tlsSamples : List Evidence.TLSSample := [⟨"alternative-egress", "HA", "10.3.0.2", true, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "delivered", false⟩, ⟨"alternative-egress", "HA", "10.3.0.2", false, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "rejected", true⟩, ⟨"central-management", "HA", "10.2.0.2", true, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "delivered", false⟩, ⟨"central-management", "HA", "10.2.0.2", false, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "rejected", true⟩, ⟨"management-vlan", "AW", "10.96.0.2", true, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "delivered", false⟩, ⟨"management-vlan", "AW", "10.96.0.2", false, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "rejected", true⟩]

theorem supplemental_tls_recorded_outcomes : Evidence.TLSRecordedOutcomes tlsSamples := by unfold Evidence.TLSRecordedOutcomes tlsSamples; decide

def caExchanges : List Evidence.CAExchange := [⟨"ca-local", "inner-a.msc.test", "inner-b.msc.test", "ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER", "good", true, 3⟩, ⟨"ca-local", "outer-a.msc.test", "outer-b.msc.test", "ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER", "good", true, 3⟩, ⟨"ca-enterprise", "inner-a.msc.test", "inner-b.msc.test", "ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER", "good", true, 3⟩, ⟨"ca-enterprise", "outer-a.msc.test", "outer-b.msc.test", "ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER", "good", true, 3⟩, ⟨"ca-central", "inner-a.msc.test", "inner-b.msc.test", "ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER", "good", true, 3⟩, ⟨"ca-central", "outer-a.msc.test", "outer-b.msc.test", "ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER", "good", true, 3⟩]

theorem observed_good_crl_authentication_exchanges : Evidence.RecordedCertificateExchanges caExchanges := by unfold Evidence.RecordedCertificateExchanges caExchanges; decide

def ospfCounts : List (String × String × Nat × Nat) := [("routing-ospf-black", "FA", 1, 1), ("routing-ospf-black", "FB", 1, 1), ("routing-ospf-red", "HA", 1, 1), ("routing-ospf-red", "HB", 1, 1)]

theorem recorded_ospf_neighbors_and_routes : ospfCounts ≠ [] ∧ ∀ s ∈ ospfCounts, 0 < s.2.2.1 ∧ 0 < s.2.2.2 := by unfold ospfCounts; decide

def relayCounts : List (Nat × Nat × Nat) := [(1, 1, 1)]

theorem recorded_relay_both_branches : relayCounts ≠ [] ∧ ∀ s ∈ relayCounts, 0 < s.1 ∧ 0 < s.2.1 ∧ s.2.2 = s.1 := by unfold relayCounts; decide

end TDN.Imported.Supplemental
