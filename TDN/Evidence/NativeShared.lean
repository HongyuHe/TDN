import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def snapshot : Evidence.Snapshot where

  id := "native-shared-four-levels-20261017T2240Z-scope-v2"

  manifestSha256 := "509c0a063a1b131052981fb2e9ab70992084937b72bad2a8f287d91c84f7aa0d"

  snapshotSha256 := "ef5ca169ad798bcec88f661f4546c02c7d4b5eb0006974530b33cc0b707f025f"

  devices := [⟨"NF_BLACK", "transport", none, none, .observed, ["obs-00002", "obs-00105"]⟩, ⟨"NF_GF_A", "gray-firewall", some "A", none, .observed, ["obs-00004", "obs-00124"]⟩, ⟨"NF_R_A1", "host", some "A", some "TOP_SECRET", .observed, ["obs-00006", "obs-00141"]⟩, ⟨"NF_I_A1", "inner", some "A", some "TOP_SECRET", .observed, ["obs-00008", "obs-00153"]⟩, ⟨"NF_G_A1", "switch", some "A", some "TOP_SECRET", .observed, ["obs-00010", "obs-00171"]⟩, ⟨"NF_O_A1", "outer", some "A", some "shared", .observed, ["obs-00012", "obs-00190"]⟩, ⟨"NF_OF_A1", "firewall", some "A", some "S1", .observed, ["obs-00014", "obs-00208"]⟩, ⟨"NF_R_A2", "host", some "A", some "SECRET_US_ONLY", .observed, ["obs-00016", "obs-00227"]⟩, ⟨"NF_I_A2", "inner", some "A", some "SECRET_US_ONLY", .observed, ["obs-00018", "obs-00239"]⟩, ⟨"NF_G_A2", "switch", some "A", some "SECRET_US_ONLY", .observed, ["obs-00020", "obs-00257"]⟩, ⟨"NF_GF_B", "gray-firewall", some "B", none, .observed, ["obs-00022", "obs-00276"]⟩, ⟨"NF_R_B1", "host", some "B", some "TOP_SECRET", .observed, ["obs-00024", "obs-00293"]⟩, ⟨"NF_I_B1", "inner", some "B", some "TOP_SECRET", .observed, ["obs-00026", "obs-00305"]⟩, ⟨"NF_G_B1", "switch", some "B", some "TOP_SECRET", .observed, ["obs-00028", "obs-00323"]⟩, ⟨"NF_O_B1", "outer", some "B", some "shared", .observed, ["obs-00030", "obs-00342"]⟩, ⟨"NF_OF_B1", "firewall", some "B", some "S1", .observed, ["obs-00032", "obs-00360"]⟩, ⟨"NF_R_B2", "host", some "B", some "SECRET_US_ONLY", .observed, ["obs-00034", "obs-00379"]⟩, ⟨"NF_I_B2", "inner", some "B", some "SECRET_US_ONLY", .observed, ["obs-00036", "obs-00391"]⟩, ⟨"NF_G_B2", "switch", some "B", some "SECRET_US_ONLY", .observed, ["obs-00038", "obs-00409"]⟩, ⟨"NF_R_A3", "host", some "A", some "SECRET_COALITION", .observed, ["obs-00040", "obs-00428"]⟩, ⟨"NF_I_A3", "inner", some "A", some "SECRET_COALITION", .observed, ["obs-00042", "obs-00440"]⟩, ⟨"NF_G_A3", "switch", some "A", some "SECRET_COALITION", .observed, ["obs-00044", "obs-00458"]⟩, ⟨"NF_R_B3", "host", some "B", some "SECRET_COALITION", .observed, ["obs-00046", "obs-00477"]⟩, ⟨"NF_I_B3", "inner", some "B", some "SECRET_COALITION", .observed, ["obs-00048", "obs-00489"]⟩, ⟨"NF_G_B3", "switch", some "B", some "SECRET_COALITION", .observed, ["obs-00050", "obs-00507"]⟩, ⟨"NF_R_A4", "host", some "A", some "UNCLASSIFIED", .observed, ["obs-00052", "obs-00526"]⟩, ⟨"NF_I_A4", "inner", some "A", some "UNCLASSIFIED", .observed, ["obs-00054", "obs-00538"]⟩, ⟨"NF_G_A4", "switch", some "A", some "UNCLASSIFIED", .observed, ["obs-00056", "obs-00556"]⟩, ⟨"NF_R_B4", "host", some "B", some "UNCLASSIFIED", .observed, ["obs-00058", "obs-00575"]⟩, ⟨"NF_I_B4", "inner", some "B", some "UNCLASSIFIED", .observed, ["obs-00060", "obs-00587"]⟩, ⟨"NF_G_B4", "switch", some "B", some "UNCLASSIFIED", .observed, ["obs-00062", "obs-00605"]⟩]

  tunnels := [⟨"NF_I_A1:tunnel", "NF_I_A1", "NF_I_B1", "inner", "IPsec", "tunnel", .observed, ["obs-00155", "obs-00157", "obs-00158", "obs-00159", "obs-00149", "obs-00148"]⟩, ⟨"NF_O_A1:tunnel", "NF_O_A1", "NF_O_B1", "outer", "IPsec", "tunnel", .observed, ["obs-00192", "obs-00194", "obs-00195", "obs-00196", "obs-00186", "obs-00185"]⟩, ⟨"NF_I_A2:tunnel", "NF_I_A2", "NF_I_B2", "inner", "IPsec", "tunnel", .observed, ["obs-00241", "obs-00243", "obs-00244", "obs-00245", "obs-00235", "obs-00234"]⟩, ⟨"NF_I_B1:tunnel", "NF_I_B1", "NF_I_A1", "inner", "IPsec", "tunnel", .observed, ["obs-00307", "obs-00309", "obs-00310", "obs-00311", "obs-00301", "obs-00300"]⟩, ⟨"NF_O_B1:tunnel", "NF_O_B1", "NF_O_A1", "outer", "IPsec", "tunnel", .observed, ["obs-00344", "obs-00346", "obs-00347", "obs-00348", "obs-00338", "obs-00337"]⟩, ⟨"NF_I_B2:tunnel", "NF_I_B2", "NF_I_A2", "inner", "IPsec", "tunnel", .observed, ["obs-00393", "obs-00395", "obs-00396", "obs-00397", "obs-00387", "obs-00386"]⟩, ⟨"NF_I_A3:tunnel", "NF_I_A3", "NF_I_B3", "inner", "IPsec", "tunnel", .observed, ["obs-00442", "obs-00444", "obs-00445", "obs-00446", "obs-00436", "obs-00435"]⟩, ⟨"NF_I_B3:tunnel", "NF_I_B3", "NF_I_A3", "inner", "IPsec", "tunnel", .observed, ["obs-00491", "obs-00493", "obs-00494", "obs-00495", "obs-00485", "obs-00484"]⟩, ⟨"NF_I_A4:tunnel", "NF_I_A4", "NF_I_B4", "inner", "IPsec", "tunnel", .observed, ["obs-00540", "obs-00542", "obs-00543", "obs-00544", "obs-00534", "obs-00533"]⟩, ⟨"NF_I_B4:tunnel", "NF_I_B4", "NF_I_A4", "inner", "IPsec", "tunnel", .observed, ["obs-00589", "obs-00591", "obs-00592", "obs-00593", "obs-00583", "obs-00582"]⟩]

  probes := [⟨"probe-obs-00614", "NF_R_A1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00614"]⟩, ⟨"probe-obs-00615", "NF_R_A1", "10.2.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00615"]⟩, ⟨"probe-obs-00616", "NF_R_A1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00616"]⟩, ⟨"probe-obs-00617", "NF_R_A1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00617"]⟩, ⟨"probe-obs-00618", "NF_R_A1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00618"]⟩, ⟨"probe-obs-00619", "NF_R_A1", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00619"]⟩, ⟨"probe-obs-00620", "NF_R_A1", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00620"]⟩, ⟨"probe-obs-00621", "NF_R_A2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00621"]⟩, ⟨"probe-obs-00622", "NF_R_A2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00622"]⟩, ⟨"probe-obs-00623", "NF_R_A2", "10.2.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00623"]⟩, ⟨"probe-obs-00624", "NF_R_A2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00624"]⟩, ⟨"probe-obs-00625", "NF_R_A2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00625"]⟩, ⟨"probe-obs-00626", "NF_R_A2", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00626"]⟩, ⟨"probe-obs-00627", "NF_R_A2", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00627"]⟩, ⟨"probe-obs-00628", "NF_R_B1", "10.1.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00628"]⟩, ⟨"probe-obs-00629", "NF_R_B1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00629"]⟩, ⟨"probe-obs-00630", "NF_R_B1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00630"]⟩, ⟨"probe-obs-00631", "NF_R_B1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00631"]⟩, ⟨"probe-obs-00632", "NF_R_B1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00632"]⟩, ⟨"probe-obs-00633", "NF_R_B1", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00633"]⟩, ⟨"probe-obs-00634", "NF_R_B1", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00634"]⟩, ⟨"probe-obs-00635", "NF_R_B2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00635"]⟩, ⟨"probe-obs-00636", "NF_R_B2", "10.1.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00636"]⟩, ⟨"probe-obs-00637", "NF_R_B2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00637"]⟩, ⟨"probe-obs-00638", "NF_R_B2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00638"]⟩, ⟨"probe-obs-00639", "NF_R_B2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00639"]⟩, ⟨"probe-obs-00640", "NF_R_B2", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00640"]⟩, ⟨"probe-obs-00641", "NF_R_B2", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00641"]⟩, ⟨"probe-obs-00642", "NF_R_A3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00642"]⟩, ⟨"probe-obs-00643", "NF_R_A3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00643"]⟩, ⟨"probe-obs-00644", "NF_R_A3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00644"]⟩, ⟨"probe-obs-00645", "NF_R_A3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00645"]⟩, ⟨"probe-obs-00646", "NF_R_A3", "10.2.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00646"]⟩, ⟨"probe-obs-00647", "NF_R_A3", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00647"]⟩, ⟨"probe-obs-00648", "NF_R_A3", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00648"]⟩, ⟨"probe-obs-00649", "NF_R_B3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00649"]⟩, ⟨"probe-obs-00650", "NF_R_B3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00650"]⟩, ⟨"probe-obs-00651", "NF_R_B3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00651"]⟩, ⟨"probe-obs-00652", "NF_R_B3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00652"]⟩, ⟨"probe-obs-00653", "NF_R_B3", "10.1.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00653"]⟩, ⟨"probe-obs-00654", "NF_R_B3", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00654"]⟩, ⟨"probe-obs-00655", "NF_R_B3", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00655"]⟩, ⟨"probe-obs-00656", "NF_R_A4", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00656"]⟩, ⟨"probe-obs-00657", "NF_R_A4", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00657"]⟩, ⟨"probe-obs-00658", "NF_R_A4", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00658"]⟩, ⟨"probe-obs-00659", "NF_R_A4", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00659"]⟩, ⟨"probe-obs-00660", "NF_R_A4", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00660"]⟩, ⟨"probe-obs-00661", "NF_R_A4", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00661"]⟩, ⟨"probe-obs-00662", "NF_R_A4", "10.2.4.10", "same-level useful traffic", "delivered", .observed, ["obs-00662"]⟩, ⟨"probe-obs-00663", "NF_R_B4", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00663"]⟩, ⟨"probe-obs-00664", "NF_R_B4", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00664"]⟩, ⟨"probe-obs-00665", "NF_R_B4", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00665"]⟩, ⟨"probe-obs-00666", "NF_R_B4", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00666"]⟩, ⟨"probe-obs-00667", "NF_R_B4", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00667"]⟩, ⟨"probe-obs-00668", "NF_R_B4", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00668"]⟩, ⟨"probe-obs-00669", "NF_R_B4", "10.1.4.10", "same-level useful traffic", "delivered", .observed, ["obs-00669"]⟩]

lemma observed_provenance : Evidence.HasProvenance snapshot := by unfold Evidence.HasProvenance snapshot; decide

theorem useful_observed_traffic : Evidence.HasObservedSuccess snapshot := by unfold Evidence.HasObservedSuccess snapshot; decide

theorem observed_ipsec_tunnel_modes : Evidence.IPsecTunnelModes snapshot := by unfold Evidence.IPsecTunnelModes snapshot; decide

theorem observed_inner_peers_same_declared_level : Evidence.InnerPeersSameDeclaredLevel snapshot := by unfold Evidence.InnerPeersSameDeclaredLevel snapshot; decide

def chain_NF_BLACK_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .ingress "p11", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .ingress "p21", .protocol "ospf"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NF_BLACK_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NF_BLACK_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_BLACK_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_BLACK_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_BLACK_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_GF_A_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_NF_GF_A_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "s1", .egress "g1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "s1", .egress "g1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "g1", .egress "s1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "g1", .egress "s1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "s2", .egress "g2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "s2", .egress "g2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "g2", .egress "s2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "g2", .egress "s2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "s3", .egress "g3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "s3", .egress "g3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "g3", .egress "s3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "g3", .egress "s3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "s4", .egress "g4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "s4", .egress "g4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "g4", .egress "s4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "g4", .egress "s4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NF_GF_A_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_NF_GF_A_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_GF_A_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_GF_A_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NF_R_A1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_R_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_I_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_NF_I_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_NF_I_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NF_I_A1_filters4_FORWARD; decide

theorem chain_NF_I_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NF_I_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NF_I_A1_filters4_FORWARD "red" "gray" chain_NF_I_A1_filters4_FORWARD_guarded p accepted

def chain_NF_I_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_I_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_I_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NF_G_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NF_G_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_G_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_G_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_O_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NF_O_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

def chain_NF_O_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NF_O_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_O_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_O_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_OF_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 2887060225 2887060225, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NF_OF_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NF_OF_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 2887060226 2887060226, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NF_OF_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_OF_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_OF_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NF_R_A2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_R_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_I_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_NF_I_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_NF_I_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NF_I_A2_filters4_FORWARD; decide

theorem chain_NF_I_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NF_I_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NF_I_A2_filters4_FORWARD "red" "gray" chain_NF_I_A2_filters4_FORWARD_guarded p accepted

def chain_NF_I_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_I_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_I_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NF_G_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NF_G_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_G_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_G_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_GF_B_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_NF_GF_B_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "s1", .egress "g1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "s1", .egress "g1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "g1", .egress "s1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "g1", .egress "s1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "s2", .egress "g2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "s2", .egress "g2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "g2", .egress "s2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "g2", .egress "s2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "s3", .egress "g3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "s3", .egress "g3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "g3", .egress "s3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "g3", .egress "s3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "s4", .egress "g4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "s4", .egress "g4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "g4", .egress "s4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "g4", .egress "s4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NF_GF_B_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_NF_GF_B_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_GF_B_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_GF_B_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NF_R_B1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_R_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_I_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_NF_I_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_NF_I_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NF_I_B1_filters4_FORWARD; decide

theorem chain_NF_I_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NF_I_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NF_I_B1_filters4_FORWARD "red" "gray" chain_NF_I_B1_filters4_FORWARD_guarded p accepted

def chain_NF_I_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_I_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_I_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NF_G_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NF_G_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_G_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_G_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_O_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NF_O_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

def chain_NF_O_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NF_O_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_O_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_O_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_OF_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 2887062785 2887062785, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NF_OF_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NF_OF_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 2887062786 2887062786, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NF_OF_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_OF_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_OF_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NF_R_B2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_R_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_I_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_NF_I_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_NF_I_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NF_I_B2_filters4_FORWARD; decide

theorem chain_NF_I_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NF_I_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NF_I_B2_filters4_FORWARD "red" "gray" chain_NF_I_B2_filters4_FORWARD_guarded p accepted

def chain_NF_I_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_I_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_I_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NF_G_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NF_G_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_G_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_G_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NF_R_A3_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_A3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_R_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_I_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_A3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 103], .allow⟩]

lemma chain_NF_I_A3_filters4_FORWARD_guarded : ∀ r ∈ chain_NF_I_A3_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NF_I_A3_filters4_FORWARD; decide

theorem chain_NF_I_A3_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NF_I_A3_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NF_I_A3_filters4_FORWARD "red" "gray" chain_NF_I_A3_filters4_FORWARD_guarded p accepted

def chain_NF_I_A3_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_I_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_I_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NF_G_A3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NF_G_A3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_G_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_G_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_B3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NF_R_B3_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_B3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_B3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_R_B3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_B3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_I_B3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_B3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 103], .allow⟩]

lemma chain_NF_I_B3_filters4_FORWARD_guarded : ∀ r ∈ chain_NF_I_B3_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NF_I_B3_filters4_FORWARD; decide

theorem chain_NF_I_B3_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NF_I_B3_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NF_I_B3_filters4_FORWARD "red" "gray" chain_NF_I_B3_filters4_FORWARD_guarded p accepted

def chain_NF_I_B3_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_B3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_I_B3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_I_B3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_B3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NF_G_B3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NF_G_B3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_B3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_G_B3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_G_B3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_A4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NF_R_A4_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_A4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_A4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_R_A4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_A4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_I_A4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_A4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 104], .allow⟩]

lemma chain_NF_I_A4_filters4_FORWARD_guarded : ∀ r ∈ chain_NF_I_A4_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NF_I_A4_filters4_FORWARD; decide

theorem chain_NF_I_A4_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NF_I_A4_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NF_I_A4_filters4_FORWARD "red" "gray" chain_NF_I_A4_filters4_FORWARD_guarded p accepted

def chain_NF_I_A4_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_A4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_I_A4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_I_A4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_A4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NF_G_A4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NF_G_A4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_A4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_G_A4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_G_A4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_B4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NF_R_B4_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_B4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_R_B4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_R_B4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_R_B4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_I_B4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_B4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 104], .allow⟩]

lemma chain_NF_I_B4_filters4_FORWARD_guarded : ∀ r ∈ chain_NF_I_B4_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NF_I_B4_filters4_FORWARD; decide

theorem chain_NF_I_B4_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NF_I_B4_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NF_I_B4_filters4_FORWARD "red" "gray" chain_NF_I_B4_filters4_FORWARD_guarded p accepted

def chain_NF_I_B4_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NF_I_B4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_I_B4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_I_B4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_B4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NF_G_B4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NF_G_B4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NF_G_B4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NF_G_B4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NF_G_B4_filters6_OUTPUT : List PacketPolicy.Rule := []

def observedESPHardLifetimes : List Evidence.HardLifetimeFact := [⟨"NF_I_A1", 0, 3600⟩, ⟨"NF_I_A1", 1, 3600⟩, ⟨"NF_O_A1", 0, 3600⟩, ⟨"NF_O_A1", 1, 3600⟩, ⟨"NF_I_A2", 0, 3600⟩, ⟨"NF_I_A2", 1, 3600⟩, ⟨"NF_I_B1", 0, 3600⟩, ⟨"NF_I_B1", 1, 3600⟩, ⟨"NF_O_B1", 0, 3600⟩, ⟨"NF_O_B1", 1, 3600⟩, ⟨"NF_I_B2", 0, 3600⟩, ⟨"NF_I_B2", 1, 3600⟩, ⟨"NF_I_A3", 0, 3600⟩, ⟨"NF_I_A3", 1, 3600⟩, ⟨"NF_I_B3", 0, 3600⟩, ⟨"NF_I_B3", 1, 3600⟩, ⟨"NF_I_A4", 0, 3600⟩, ⟨"NF_I_A4", 1, 3600⟩, ⟨"NF_I_B4", 0, 3600⟩, ⟨"NF_I_B4", 1, 3600⟩]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩, ⟨6, 2, .gcm, .gcm, false⟩, ⟨7, 2, .gcm, .gcm, false⟩, ⟨8, 2, .gcm, .gcm, false⟩, ⟨9, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

def loadedVPNModePolicies : List Targets.VPNModePolicy := [⟨"NF_I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_A3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_B3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_A4/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_B4/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide

end TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2
