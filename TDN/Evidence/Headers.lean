import TDN.Evidence.LoadedBaseline

import TDN.Targets.Headers

namespace TDN.Imported.Headers

open TDN.Imported.baseline_loaded_20261017T2117Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def gateways : List Targets.GatewayHeaderPolicy := [⟨"I_A1", false, "gray", true, false, false, [chain_I_A1_filters4_INPUT, chain_I_A1_filters4_FORWARD, chain_I_A1_filters4_OUTPUT], [], [chain_I_A1_filters4_INPUT, chain_I_A1_filters4_FORWARD], []⟩, ⟨"O_A1", true, "black", true, false, true, [chain_O_A1_filters4_INPUT, chain_O_A1_filters4_FORWARD, chain_O_A1_filters4_OUTPUT], [], [chain_O_A1_filters4_INPUT, chain_O_A1_filters4_FORWARD], []⟩, ⟨"I_A2", false, "gray", true, false, false, [chain_I_A2_filters4_INPUT, chain_I_A2_filters4_FORWARD, chain_I_A2_filters4_OUTPUT], [], [chain_I_A2_filters4_INPUT, chain_I_A2_filters4_FORWARD], []⟩, ⟨"O_A2", true, "black", true, false, true, [chain_O_A2_filters4_INPUT, chain_O_A2_filters4_FORWARD, chain_O_A2_filters4_OUTPUT], [], [chain_O_A2_filters4_INPUT, chain_O_A2_filters4_FORWARD], []⟩, ⟨"I_B1", false, "gray", true, false, false, [chain_I_B1_filters4_INPUT, chain_I_B1_filters4_FORWARD, chain_I_B1_filters4_OUTPUT], [], [chain_I_B1_filters4_INPUT, chain_I_B1_filters4_FORWARD], []⟩, ⟨"O_B1", true, "black", true, false, true, [chain_O_B1_filters4_INPUT, chain_O_B1_filters4_FORWARD, chain_O_B1_filters4_OUTPUT], [], [chain_O_B1_filters4_INPUT, chain_O_B1_filters4_FORWARD], []⟩, ⟨"I_B2", false, "gray", true, false, false, [chain_I_B2_filters4_INPUT, chain_I_B2_filters4_FORWARD, chain_I_B2_filters4_OUTPUT], [], [chain_I_B2_filters4_INPUT, chain_I_B2_filters4_FORWARD], []⟩, ⟨"O_B2", true, "black", true, false, true, [chain_O_B2_filters4_INPUT, chain_O_B2_filters4_FORWARD, chain_O_B2_filters4_OUTPUT], [], [chain_O_B2_filters4_INPUT, chain_O_B2_filters4_FORWARD], []⟩]

lemma all_header_certificates : ∀ g ∈ gateways, Targets.HeaderCertificate g := by unfold gateways; decide

theorem snapshot_RG038 : Targets.msc_ip_header_and_multicast_filtering gateways := Targets.header_certificates_suffice gateways (by unfold gateways; decide) all_header_certificates

end TDN.Imported.Headers
