import TDN.Evidence.NativeBaseline

import TDN.Targets.Headers

namespace TDN.Imported.NativeBaselineHeaders

open TDN.Imported.native_baseline_20261017T2237Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def gateways : List Targets.GatewayHeaderPolicy := [⟨"NB_I_A1", false, "gray", true, false, false, [chain_NB_I_A1_filters4_INPUT, chain_NB_I_A1_filters4_FORWARD, chain_NB_I_A1_filters4_OUTPUT], [], [chain_NB_I_A1_filters4_INPUT, chain_NB_I_A1_filters4_FORWARD], []⟩, ⟨"NB_O_A1", true, "black", true, false, true, [chain_NB_O_A1_filters4_INPUT, chain_NB_O_A1_filters4_FORWARD, chain_NB_O_A1_filters4_OUTPUT], [], [chain_NB_O_A1_filters4_INPUT, chain_NB_O_A1_filters4_FORWARD], []⟩, ⟨"NB_I_A2", false, "gray", true, false, false, [chain_NB_I_A2_filters4_INPUT, chain_NB_I_A2_filters4_FORWARD, chain_NB_I_A2_filters4_OUTPUT], [], [chain_NB_I_A2_filters4_INPUT, chain_NB_I_A2_filters4_FORWARD], []⟩, ⟨"NB_O_A2", true, "black", true, false, true, [chain_NB_O_A2_filters4_INPUT, chain_NB_O_A2_filters4_FORWARD, chain_NB_O_A2_filters4_OUTPUT], [], [chain_NB_O_A2_filters4_INPUT, chain_NB_O_A2_filters4_FORWARD], []⟩, ⟨"NB_I_B1", false, "gray", true, false, false, [chain_NB_I_B1_filters4_INPUT, chain_NB_I_B1_filters4_FORWARD, chain_NB_I_B1_filters4_OUTPUT], [], [chain_NB_I_B1_filters4_INPUT, chain_NB_I_B1_filters4_FORWARD], []⟩, ⟨"NB_O_B1", true, "black", true, false, true, [chain_NB_O_B1_filters4_INPUT, chain_NB_O_B1_filters4_FORWARD, chain_NB_O_B1_filters4_OUTPUT], [], [chain_NB_O_B1_filters4_INPUT, chain_NB_O_B1_filters4_FORWARD], []⟩, ⟨"NB_I_B2", false, "gray", true, false, false, [chain_NB_I_B2_filters4_INPUT, chain_NB_I_B2_filters4_FORWARD, chain_NB_I_B2_filters4_OUTPUT], [], [chain_NB_I_B2_filters4_INPUT, chain_NB_I_B2_filters4_FORWARD], []⟩, ⟨"NB_O_B2", true, "black", true, false, true, [chain_NB_O_B2_filters4_INPUT, chain_NB_O_B2_filters4_FORWARD, chain_NB_O_B2_filters4_OUTPUT], [], [chain_NB_O_B2_filters4_INPUT, chain_NB_O_B2_filters4_FORWARD], []⟩]

lemma all_header_certificates : ∀ g ∈ gateways, Targets.HeaderCertificate g := by unfold gateways; decide

theorem snapshot_RG038 : Targets.msc_ip_header_and_multicast_filtering gateways := Targets.header_certificates_suffice gateways (by unfold gateways; decide) all_header_certificates

end TDN.Imported.NativeBaselineHeaders
