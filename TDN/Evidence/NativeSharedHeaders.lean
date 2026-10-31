import TDN.Evidence.NativeShared

import TDN.Targets.Headers

namespace TDN.Imported.NativeSharedHeaders

open TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def gateways : List Targets.GatewayHeaderPolicy := [⟨"NF_I_A1", false, "gray", true, false, false, [chain_NF_I_A1_filters4_INPUT, chain_NF_I_A1_filters4_FORWARD, chain_NF_I_A1_filters4_OUTPUT], [], [chain_NF_I_A1_filters4_INPUT, chain_NF_I_A1_filters4_FORWARD], []⟩, ⟨"NF_O_A1", true, "black", true, false, true, [chain_NF_O_A1_filters4_INPUT, chain_NF_O_A1_filters4_FORWARD, chain_NF_O_A1_filters4_OUTPUT], [], [chain_NF_O_A1_filters4_INPUT, chain_NF_O_A1_filters4_FORWARD], []⟩, ⟨"NF_I_A2", false, "gray", true, false, false, [chain_NF_I_A2_filters4_INPUT, chain_NF_I_A2_filters4_FORWARD, chain_NF_I_A2_filters4_OUTPUT], [], [chain_NF_I_A2_filters4_INPUT, chain_NF_I_A2_filters4_FORWARD], []⟩, ⟨"NF_I_B1", false, "gray", true, false, false, [chain_NF_I_B1_filters4_INPUT, chain_NF_I_B1_filters4_FORWARD, chain_NF_I_B1_filters4_OUTPUT], [], [chain_NF_I_B1_filters4_INPUT, chain_NF_I_B1_filters4_FORWARD], []⟩, ⟨"NF_O_B1", true, "black", true, false, true, [chain_NF_O_B1_filters4_INPUT, chain_NF_O_B1_filters4_FORWARD, chain_NF_O_B1_filters4_OUTPUT], [], [chain_NF_O_B1_filters4_INPUT, chain_NF_O_B1_filters4_FORWARD], []⟩, ⟨"NF_I_B2", false, "gray", true, false, false, [chain_NF_I_B2_filters4_INPUT, chain_NF_I_B2_filters4_FORWARD, chain_NF_I_B2_filters4_OUTPUT], [], [chain_NF_I_B2_filters4_INPUT, chain_NF_I_B2_filters4_FORWARD], []⟩, ⟨"NF_I_A3", false, "gray", true, false, false, [chain_NF_I_A3_filters4_INPUT, chain_NF_I_A3_filters4_FORWARD, chain_NF_I_A3_filters4_OUTPUT], [], [chain_NF_I_A3_filters4_INPUT, chain_NF_I_A3_filters4_FORWARD], []⟩, ⟨"NF_I_B3", false, "gray", true, false, false, [chain_NF_I_B3_filters4_INPUT, chain_NF_I_B3_filters4_FORWARD, chain_NF_I_B3_filters4_OUTPUT], [], [chain_NF_I_B3_filters4_INPUT, chain_NF_I_B3_filters4_FORWARD], []⟩, ⟨"NF_I_A4", false, "gray", true, false, false, [chain_NF_I_A4_filters4_INPUT, chain_NF_I_A4_filters4_FORWARD, chain_NF_I_A4_filters4_OUTPUT], [], [chain_NF_I_A4_filters4_INPUT, chain_NF_I_A4_filters4_FORWARD], []⟩, ⟨"NF_I_B4", false, "gray", true, false, false, [chain_NF_I_B4_filters4_INPUT, chain_NF_I_B4_filters4_FORWARD, chain_NF_I_B4_filters4_OUTPUT], [], [chain_NF_I_B4_filters4_INPUT, chain_NF_I_B4_filters4_FORWARD], []⟩]

lemma all_header_certificates : ∀ g ∈ gateways, Targets.HeaderCertificate g := by unfold gateways; decide

theorem snapshot_RG038 : Targets.msc_ip_header_and_multicast_filtering gateways := Targets.header_certificates_suffice gateways (by unfold gateways; decide) all_header_certificates

end TDN.Imported.NativeSharedHeaders
