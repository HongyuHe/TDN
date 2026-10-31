import TDN.Evidence.NativeSameLevel

import TDN.Targets.Headers

namespace TDN.Imported.NativeSameLevelHeaders

open TDN.Imported.native_samelevel_20261017T2242Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def gateways : List Targets.GatewayHeaderPolicy := [⟨"NT_I_A1", false, "gray", true, false, false, [chain_NT_I_A1_filters4_INPUT, chain_NT_I_A1_filters4_FORWARD, chain_NT_I_A1_filters4_OUTPUT], [], [chain_NT_I_A1_filters4_INPUT, chain_NT_I_A1_filters4_FORWARD], []⟩, ⟨"NT_O_A1", true, "black", true, false, true, [chain_NT_O_A1_filters4_INPUT, chain_NT_O_A1_filters4_FORWARD, chain_NT_O_A1_filters4_OUTPUT], [], [chain_NT_O_A1_filters4_INPUT, chain_NT_O_A1_filters4_FORWARD], []⟩, ⟨"NT_I_A2", false, "gray", true, false, false, [chain_NT_I_A2_filters4_INPUT, chain_NT_I_A2_filters4_FORWARD, chain_NT_I_A2_filters4_OUTPUT], [], [chain_NT_I_A2_filters4_INPUT, chain_NT_I_A2_filters4_FORWARD], []⟩, ⟨"NT_I_B1", false, "gray", true, false, false, [chain_NT_I_B1_filters4_INPUT, chain_NT_I_B1_filters4_FORWARD, chain_NT_I_B1_filters4_OUTPUT], [], [chain_NT_I_B1_filters4_INPUT, chain_NT_I_B1_filters4_FORWARD], []⟩, ⟨"NT_O_B1", true, "black", true, false, true, [chain_NT_O_B1_filters4_INPUT, chain_NT_O_B1_filters4_FORWARD, chain_NT_O_B1_filters4_OUTPUT], [], [chain_NT_O_B1_filters4_INPUT, chain_NT_O_B1_filters4_FORWARD], []⟩, ⟨"NT_I_B2", false, "gray", true, false, false, [chain_NT_I_B2_filters4_INPUT, chain_NT_I_B2_filters4_FORWARD, chain_NT_I_B2_filters4_OUTPUT], [], [chain_NT_I_B2_filters4_INPUT, chain_NT_I_B2_filters4_FORWARD], []⟩]

lemma all_header_certificates : ∀ g ∈ gateways, Targets.HeaderCertificate g := by unfold gateways; decide

theorem snapshot_RG038 : Targets.msc_ip_header_and_multicast_filtering gateways := Targets.header_certificates_suffice gateways (by unfold gateways; decide) all_header_certificates

end TDN.Imported.NativeSameLevelHeaders
