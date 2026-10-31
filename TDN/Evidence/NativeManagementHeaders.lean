import TDN.Evidence.NativeManagement

import TDN.Targets.Headers

namespace TDN.Imported.NativeManagementHeaders

open TDN.Imported.native_management_20261017T2241Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def gateways : List Targets.GatewayHeaderPolicy := [⟨"NM_I_A1", false, "gray", true, false, false, [chain_NM_I_A1_filters4_INPUT, chain_NM_I_A1_filters4_FORWARD, chain_NM_I_A1_filters4_OUTPUT], [], [chain_NM_I_A1_filters4_INPUT, chain_NM_I_A1_filters4_FORWARD], []⟩, ⟨"NM_O_A1", true, "black", true, false, true, [chain_NM_O_A1_filters4_INPUT, chain_NM_O_A1_filters4_FORWARD, chain_NM_O_A1_filters4_OUTPUT], [], [chain_NM_O_A1_filters4_INPUT, chain_NM_O_A1_filters4_FORWARD], []⟩, ⟨"NM_I_A2", false, "gray", true, false, false, [chain_NM_I_A2_filters4_INPUT, chain_NM_I_A2_filters4_FORWARD, chain_NM_I_A2_filters4_OUTPUT], [], [chain_NM_I_A2_filters4_INPUT, chain_NM_I_A2_filters4_FORWARD], []⟩, ⟨"NM_O_A2", true, "black", true, false, true, [chain_NM_O_A2_filters4_INPUT, chain_NM_O_A2_filters4_FORWARD, chain_NM_O_A2_filters4_OUTPUT], [], [chain_NM_O_A2_filters4_INPUT, chain_NM_O_A2_filters4_FORWARD], []⟩, ⟨"NM_I_B1", false, "gray", true, false, false, [chain_NM_I_B1_filters4_INPUT, chain_NM_I_B1_filters4_FORWARD, chain_NM_I_B1_filters4_OUTPUT], [], [chain_NM_I_B1_filters4_INPUT, chain_NM_I_B1_filters4_FORWARD], []⟩, ⟨"NM_O_B1", true, "black", true, false, true, [chain_NM_O_B1_filters4_INPUT, chain_NM_O_B1_filters4_FORWARD, chain_NM_O_B1_filters4_OUTPUT], [], [chain_NM_O_B1_filters4_INPUT, chain_NM_O_B1_filters4_FORWARD], []⟩, ⟨"NM_I_B2", false, "gray", true, false, false, [chain_NM_I_B2_filters4_INPUT, chain_NM_I_B2_filters4_FORWARD, chain_NM_I_B2_filters4_OUTPUT], [], [chain_NM_I_B2_filters4_INPUT, chain_NM_I_B2_filters4_FORWARD], []⟩, ⟨"NM_O_B2", true, "black", true, false, true, [chain_NM_O_B2_filters4_INPUT, chain_NM_O_B2_filters4_FORWARD, chain_NM_O_B2_filters4_OUTPUT], [], [chain_NM_O_B2_filters4_INPUT, chain_NM_O_B2_filters4_FORWARD], []⟩]

theorem all_header_certificates : ∀ g ∈ gateways, Targets.HeaderCertificate g := by unfold gateways; decide

theorem snapshot_RG038 : Targets.msc_ip_header_and_multicast_filtering gateways := Targets.header_certificates_suffice gateways (by unfold gateways; decide) all_header_certificates

end TDN.Imported.NativeManagementHeaders
