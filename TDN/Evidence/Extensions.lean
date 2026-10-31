import TDN.Evidence.SupplementalTypes

import TDN.Semantics.BridgePolicy

namespace TDN.Imported.Extensions

set_option maxRecDepth 100000

def httpChain0 := BridgePolicy.chain 168493057 168558594

theorem http_exception_0_bounded (p : BridgePolicy.Frame) (h4 : p.etherType = 2048) (ht : p.ipProtocol = 6) (ha : Filter.evaluate httpChain0 .deny p = .allow) : BridgePolicy.HTTPRequest 168493057 168558594 p ∨ BridgePolicy.HTTPResponse 168493057 168558594 p := BridgePolicy.accepted_tcp_is_bounded _ _ p h4 ht ha

def httpChain1 := BridgePolicy.chain 168493057 168558594

theorem http_exception_1_bounded (p : BridgePolicy.Frame) (h4 : p.etherType = 2048) (ht : p.ipProtocol = 6) (ha : Filter.evaluate httpChain1 .deny p = .allow) : BridgePolicy.HTTPRequest 168493057 168558594 p ∨ BridgePolicy.HTTPResponse 168493057 168558594 p := BridgePolicy.accepted_tcp_is_bounded _ _ p h4 ht ha

def revocationStatuses : List (String × List String) := [("http-crl-v1", ["good", "revoked"]), ("http-ocsp-v1", ["good", "revoked"])]

theorem observed_revocation_status_pairs : revocationStatuses ≠ [] ∧ ∀ c ∈ revocationStatuses, c.2 = ["good","revoked"] := by unfold revocationStatuses; decide

def eapResults : List (String × String × Bool × String) := [("eap-tls-forward-v3", "TLSv1.2", true, "not_attempted"), ("eap-tls-forward-v4", "TLSv1.2", true, "not_attempted"), ("eap-tls-forward-v5", "TLSv1.2", true, "not_attempted"), ("eap-tls-reverse-v3", "TLSv1.2", true, "not_attempted"), ("eap-tls-reverse-v4", "TLSv1.2", true, "runtime_error"), ("eap-tls-reverse-v5", "TLSv1.2", true, "not_attempted")]

theorem eap_authentication_without_successful_data_probe : eapResults ≠ [] ∧ ∀ e ∈ eapResults, e.2.1 = "TLSv1.2" ∧ e.2.2.1 = true ∧ e.2.2.2 ∈ ["not_attempted","runtime_error"] := by unfold eapResults; decide

def awSamples : List Evidence.TLSSample := [⟨"aw-placement", "node-1.twinet-msc.netsyn-pg0.clemson.cloudlab.us", "management-test-listener", true, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "delivered", false⟩, ⟨"aw-placement", "node-1.twinet-msc.netsyn-pg0.clemson.cloudlab.us", "management-test-listener", false, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "rejected", true⟩, ⟨"aw-placement", "csfc-aw-vm", "management-test-listener", true, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "delivered", false⟩, ⟨"aw-placement", "csfc-aw-vm", "management-test-listener", false, "TLSv1.3", "TLS_AES_256_GCM_SHA384", "rejected", true⟩]

theorem recorded_host_and_guest_tls_use : Evidence.TLSRecordedOutcomes awSamples := by unfold Evidence.TLSRecordedOutcomes awSamples; decide

def redundancyProbes : List Evidence.MechanismProbe := [⟨"primary-1", "delivered", "delivered", 3, 3⟩, ⟨"primary-2", "delivered", "delivered", 3, 3⟩, ⟨"primary-3", "delivered", "delivered", 3, 3⟩, ⟨"primary-4", "delivered", "delivered", 3, 3⟩, ⟨"active-sharing-1", "delivered", "delivered", 3, 3⟩, ⟨"active-sharing-2", "delivered", "delivered", 3, 3⟩, ⟨"active-sharing-3", "delivered", "delivered", 3, 3⟩, ⟨"active-sharing-4", "delivered", "delivered", 3, 3⟩, ⟨"primary-outage-1", "no_reply", "no_reply", 3, 0⟩, ⟨"standby-restored-1", "delivered", "delivered", 3, 3⟩, ⟨"standby-restored-2", "delivered", "delivered", 3, 3⟩, ⟨"standby-restored-3", "delivered", "delivered", 3, 3⟩, ⟨"standby-restored-4", "delivered", "delivered", 3, 3⟩, ⟨"original-restored-1", "delivered", "delivered", 3, 3⟩, ⟨"original-restored-2", "delivered", "delivered", 3, 3⟩, ⟨"original-restored-3", "delivered", "delivered", 3, 3⟩, ⟨"original-restored-4", "delivered", "delivered", 3, 3⟩]

theorem recorded_manual_redundancy_probe_outcomes : redundancyProbes ≠ [] ∧ ∀ p ∈ redundancyProbes, p.expected = p.observed := by unfold redundancyProbes; decide

theorem outage_and_restoration_witnesses : (∃ p ∈ redundancyProbes, p.observed = "no_reply") ∧ (∃ p ∈ redundancyProbes, p.id = "standby-restored-1" ∧ 0 < p.received) := by unfold redundancyProbes; decide

end TDN.Imported.Extensions
