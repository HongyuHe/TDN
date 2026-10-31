import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.redundant_four_levels_coherent_20261017T2208Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def snapshot : Evidence.Snapshot where

  id := "redundant-four-levels-coherent-20261017T2208Z"

  manifestSha256 := "eec0c65df1d1b1463413d1f34965790be5c92e3d91325728e57fcacfa1af8c21"

  snapshotSha256 := "5ebc44bea84b9a3b9dcf365720d52261be7906319151a2170af006a21fb79d54"

  devices := [⟨"BLACK", "transport", none, none, .observed, ["obs-00002", "obs-00123"]⟩, ⟨"GF_A", "gray-firewall", some "A", none, .observed, ["obs-00004", "obs-00135"]⟩, ⟨"R_A1", "host", some "A", some "TOP_SECRET", .observed, ["obs-00006", "obs-00147"]⟩, ⟨"I_A1", "inner", some "A", some "TOP_SECRET", .observed, ["obs-00008", "obs-00159"]⟩, ⟨"G_A1", "switch", some "A", some "TOP_SECRET", .observed, ["obs-00010", "obs-00177"]⟩, ⟨"O_A1", "outer", some "A", some "shared", .observed, ["obs-00012", "obs-00189"]⟩, ⟨"OF_A1", "firewall", some "A", some "S1", .observed, ["obs-00014", "obs-00207"]⟩, ⟨"R_A2", "host", some "A", some "SECRET_US_ONLY", .observed, ["obs-00016", "obs-00219"]⟩, ⟨"I_A2", "inner", some "A", some "SECRET_US_ONLY", .observed, ["obs-00018", "obs-00231"]⟩, ⟨"G_A2", "switch", some "A", some "SECRET_US_ONLY", .observed, ["obs-00020", "obs-00249"]⟩, ⟨"GF_B", "gray-firewall", some "B", none, .observed, ["obs-00022", "obs-00261"]⟩, ⟨"R_B1", "host", some "B", some "TOP_SECRET", .observed, ["obs-00024", "obs-00273"]⟩, ⟨"I_B1", "inner", some "B", some "TOP_SECRET", .observed, ["obs-00026", "obs-00285"]⟩, ⟨"G_B1", "switch", some "B", some "TOP_SECRET", .observed, ["obs-00028", "obs-00303"]⟩, ⟨"O_B1", "outer", some "B", some "shared", .observed, ["obs-00030", "obs-00315"]⟩, ⟨"OF_B1", "firewall", some "B", some "S1", .observed, ["obs-00032", "obs-00333"]⟩, ⟨"R_B2", "host", some "B", some "SECRET_US_ONLY", .observed, ["obs-00034", "obs-00345"]⟩, ⟨"I_B2", "inner", some "B", some "SECRET_US_ONLY", .observed, ["obs-00036", "obs-00357"]⟩, ⟨"G_B2", "switch", some "B", some "SECRET_US_ONLY", .observed, ["obs-00038", "obs-00375"]⟩, ⟨"R_A3", "host", some "A", some "SECRET_COALITION", .observed, ["obs-00040", "obs-00387"]⟩, ⟨"I_A3", "inner", some "A", some "SECRET_COALITION", .observed, ["obs-00042", "obs-00399"]⟩, ⟨"G_A3", "switch", some "A", some "SECRET_COALITION", .observed, ["obs-00044", "obs-00417"]⟩, ⟨"R_B3", "host", some "B", some "SECRET_COALITION", .observed, ["obs-00046", "obs-00429"]⟩, ⟨"I_B3", "inner", some "B", some "SECRET_COALITION", .observed, ["obs-00048", "obs-00441"]⟩, ⟨"G_B3", "switch", some "B", some "SECRET_COALITION", .observed, ["obs-00050", "obs-00459"]⟩, ⟨"O_A2", "outer", some "A", some "shared", .observed, ["obs-00052", "obs-00471"]⟩, ⟨"OF_A2", "firewall", some "A", some "S2", .observed, ["obs-00054", "obs-00489"]⟩, ⟨"O_B2", "outer", some "B", some "shared", .observed, ["obs-00056", "obs-00501"]⟩, ⟨"OF_B2", "firewall", some "B", some "S2", .observed, ["obs-00058", "obs-00519"]⟩, ⟨"GR_A", "transport", some "A", none, .observed, ["obs-00060", "obs-00531"]⟩, ⟨"GR_B", "transport", some "B", none, .observed, ["obs-00062", "obs-00543"]⟩, ⟨"R_A4", "host", some "A", some "UNCLASSIFIED", .observed, ["obs-00064", "obs-00555"]⟩, ⟨"I_A4", "inner", some "A", some "UNCLASSIFIED", .observed, ["obs-00066", "obs-00567"]⟩, ⟨"G_A4", "switch", some "A", some "UNCLASSIFIED", .observed, ["obs-00068", "obs-00585"]⟩, ⟨"R_B4", "host", some "B", some "UNCLASSIFIED", .observed, ["obs-00070", "obs-00597"]⟩, ⟨"I_B4", "inner", some "B", some "UNCLASSIFIED", .observed, ["obs-00072", "obs-00609"]⟩, ⟨"G_B4", "switch", some "B", some "UNCLASSIFIED", .observed, ["obs-00074", "obs-00627"]⟩]

  tunnels := [⟨"I_A1:tunnel", "I_A1", "I_B1", "inner", "IPsec", "tunnel", .observed, ["obs-00161", "obs-00163", "obs-00164", "obs-00165", "obs-00155", "obs-00154"]⟩, ⟨"O_A1:tunnel", "O_A1", "O_B1", "outer", "IPsec", "tunnel", .observed, ["obs-00191", "obs-00193", "obs-00194", "obs-00195", "obs-00185", "obs-00184"]⟩, ⟨"I_A2:tunnel", "I_A2", "I_B2", "inner", "IPsec", "tunnel", .observed, ["obs-00233", "obs-00235", "obs-00236", "obs-00237", "obs-00227", "obs-00226"]⟩, ⟨"I_B1:tunnel", "I_B1", "I_A1", "inner", "IPsec", "tunnel", .observed, ["obs-00287", "obs-00289", "obs-00290", "obs-00291", "obs-00281", "obs-00280"]⟩, ⟨"O_B1:tunnel", "O_B1", "O_A1", "outer", "IPsec", "tunnel", .observed, ["obs-00317", "obs-00319", "obs-00320", "obs-00321", "obs-00311", "obs-00310"]⟩, ⟨"I_B2:tunnel", "I_B2", "I_A2", "inner", "IPsec", "tunnel", .observed, ["obs-00359", "obs-00361", "obs-00362", "obs-00363", "obs-00353", "obs-00352"]⟩, ⟨"I_A3:tunnel", "I_A3", "I_B3", "inner", "IPsec", "tunnel", .observed, ["obs-00401", "obs-00403", "obs-00404", "obs-00405", "obs-00395", "obs-00394"]⟩, ⟨"I_B3:tunnel", "I_B3", "I_A3", "inner", "IPsec", "tunnel", .observed, ["obs-00443", "obs-00445", "obs-00446", "obs-00447", "obs-00437", "obs-00436"]⟩, ⟨"O_A2:tunnel", "O_A2", "O_B2", "outer", "IPsec", "tunnel", .observed, ["obs-00473", "obs-00475", "obs-00476", "obs-00477", "obs-00467", "obs-00466"]⟩, ⟨"O_B2:tunnel", "O_B2", "O_A2", "outer", "IPsec", "tunnel", .observed, ["obs-00503", "obs-00505", "obs-00506", "obs-00507", "obs-00497", "obs-00496"]⟩, ⟨"I_A4:tunnel", "I_A4", "I_B4", "inner", "IPsec", "tunnel", .observed, ["obs-00569", "obs-00571", "obs-00572", "obs-00573", "obs-00563", "obs-00562"]⟩, ⟨"I_B4:tunnel", "I_B4", "I_A4", "inner", "IPsec", "tunnel", .observed, ["obs-00611", "obs-00613", "obs-00614", "obs-00615", "obs-00605", "obs-00604"]⟩]

  probes := [⟨"probe-obs-00629", "R_A1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00629"]⟩, ⟨"probe-obs-00630", "R_A1", "10.2.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00630"]⟩, ⟨"probe-obs-00631", "R_A1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00631"]⟩, ⟨"probe-obs-00632", "R_A1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00632"]⟩, ⟨"probe-obs-00633", "R_A1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00633"]⟩, ⟨"probe-obs-00634", "R_A1", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00634"]⟩, ⟨"probe-obs-00635", "R_A1", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00635"]⟩, ⟨"probe-obs-00636", "R_A2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00636"]⟩, ⟨"probe-obs-00637", "R_A2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00637"]⟩, ⟨"probe-obs-00638", "R_A2", "10.2.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00638"]⟩, ⟨"probe-obs-00639", "R_A2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00639"]⟩, ⟨"probe-obs-00640", "R_A2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00640"]⟩, ⟨"probe-obs-00641", "R_A2", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00641"]⟩, ⟨"probe-obs-00642", "R_A2", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00642"]⟩, ⟨"probe-obs-00643", "R_B1", "10.1.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00643"]⟩, ⟨"probe-obs-00644", "R_B1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00644"]⟩, ⟨"probe-obs-00645", "R_B1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00645"]⟩, ⟨"probe-obs-00646", "R_B1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00646"]⟩, ⟨"probe-obs-00647", "R_B1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00647"]⟩, ⟨"probe-obs-00648", "R_B1", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00648"]⟩, ⟨"probe-obs-00649", "R_B1", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00649"]⟩, ⟨"probe-obs-00650", "R_B2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00650"]⟩, ⟨"probe-obs-00651", "R_B2", "10.1.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00651"]⟩, ⟨"probe-obs-00652", "R_B2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00652"]⟩, ⟨"probe-obs-00653", "R_B2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00653"]⟩, ⟨"probe-obs-00654", "R_B2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00654"]⟩, ⟨"probe-obs-00655", "R_B2", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00655"]⟩, ⟨"probe-obs-00656", "R_B2", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00656"]⟩, ⟨"probe-obs-00657", "R_A3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00657"]⟩, ⟨"probe-obs-00658", "R_A3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00658"]⟩, ⟨"probe-obs-00659", "R_A3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00659"]⟩, ⟨"probe-obs-00660", "R_A3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00660"]⟩, ⟨"probe-obs-00661", "R_A3", "10.2.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00661"]⟩, ⟨"probe-obs-00662", "R_A3", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00662"]⟩, ⟨"probe-obs-00663", "R_A3", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00663"]⟩, ⟨"probe-obs-00664", "R_B3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00664"]⟩, ⟨"probe-obs-00665", "R_B3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00665"]⟩, ⟨"probe-obs-00666", "R_B3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00666"]⟩, ⟨"probe-obs-00667", "R_B3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00667"]⟩, ⟨"probe-obs-00668", "R_B3", "10.1.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00668"]⟩, ⟨"probe-obs-00669", "R_B3", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00669"]⟩, ⟨"probe-obs-00670", "R_B3", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00670"]⟩, ⟨"probe-obs-00671", "R_A4", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00671"]⟩, ⟨"probe-obs-00672", "R_A4", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00672"]⟩, ⟨"probe-obs-00673", "R_A4", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00673"]⟩, ⟨"probe-obs-00674", "R_A4", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00674"]⟩, ⟨"probe-obs-00675", "R_A4", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00675"]⟩, ⟨"probe-obs-00676", "R_A4", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00676"]⟩, ⟨"probe-obs-00677", "R_A4", "10.2.4.10", "same-level useful traffic", "delivered", .observed, ["obs-00677"]⟩, ⟨"probe-obs-00678", "R_B4", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00678"]⟩, ⟨"probe-obs-00679", "R_B4", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00679"]⟩, ⟨"probe-obs-00680", "R_B4", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00680"]⟩, ⟨"probe-obs-00681", "R_B4", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00681"]⟩, ⟨"probe-obs-00682", "R_B4", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00682"]⟩, ⟨"probe-obs-00683", "R_B4", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00683"]⟩, ⟨"probe-obs-00684", "R_B4", "10.1.4.10", "same-level useful traffic", "delivered", .observed, ["obs-00684"]⟩]

lemma observed_provenance : Evidence.HasProvenance snapshot := by unfold Evidence.HasProvenance snapshot; decide

theorem useful_observed_traffic : Evidence.HasObservedSuccess snapshot := by unfold Evidence.HasObservedSuccess snapshot; decide

theorem observed_ipsec_tunnel_modes : Evidence.IPsecTunnelModes snapshot := by unfold Evidence.IPsecTunnelModes snapshot; decide

theorem observed_inner_peers_same_declared_level : Evidence.InnerPeersSameDeclaredLevel snapshot := by unfold Evidence.InnerPeersSameDeclaredLevel snapshot; decide

def chain_BLACK_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_BLACK_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_BLACK_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_BLACK_filters6_INPUT : List PacketPolicy.Rule := []

def chain_BLACK_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_BLACK_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_GF_A_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_GF_A_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "s1", .egress "g1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "s1", .egress "g1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "g1", .egress "s1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "g1", .egress "s1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "s2", .egress "g2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "s2", .egress "g2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "g2", .egress "s2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "g2", .egress "s2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "s3", .egress "g3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "s3", .egress "g3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "g3", .egress "s3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "g3", .egress "s3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "s4", .egress "g4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "s4", .egress "g4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "g4", .egress "s4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "g4", .egress "s4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_GF_A_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_GF_A_filters6_INPUT : List PacketPolicy.Rule := []

def chain_GF_A_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_GF_A_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_R_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_R_A1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_R_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_R_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_R_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_R_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_I_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_I_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_I_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_I_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_A1_filters4_FORWARD; decide

theorem chain_I_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_A1_filters4_FORWARD "red" "gray" chain_I_A1_filters4_FORWARD_guarded p accepted

def chain_I_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "esp"], .allow⟩]

def chain_I_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_I_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_I_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_G_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_G_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_G_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_G_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_G_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_G_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_O_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

def chain_O_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_O_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_O_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_OF_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_OF_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_OF_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_OF_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_OF_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_OF_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_R_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_R_A2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_R_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_R_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_R_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_R_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_I_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_I_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_I_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_I_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_A2_filters4_FORWARD; decide

theorem chain_I_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_A2_filters4_FORWARD "red" "gray" chain_I_A2_filters4_FORWARD_guarded p accepted

def chain_I_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "esp"], .allow⟩]

def chain_I_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_I_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_I_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_G_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_G_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_G_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_G_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_G_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_G_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_GF_B_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_GF_B_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "s1", .egress "g1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "s1", .egress "g1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "g1", .egress "s1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "g1", .egress "s1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "s2", .egress "g2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "s2", .egress "g2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "g2", .egress "s2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "g2", .egress "s2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "s3", .egress "g3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "s3", .egress "g3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "g3", .egress "s3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "g3", .egress "s3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "s4", .egress "g4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "s4", .egress "g4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "g4", .egress "s4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "g4", .egress "s4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_GF_B_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_GF_B_filters6_INPUT : List PacketPolicy.Rule := []

def chain_GF_B_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_GF_B_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_R_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_R_B1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_R_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_R_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_R_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_R_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_I_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_I_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_I_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_I_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_B1_filters4_FORWARD; decide

theorem chain_I_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_B1_filters4_FORWARD "red" "gray" chain_I_B1_filters4_FORWARD_guarded p accepted

def chain_I_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "esp"], .allow⟩]

def chain_I_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_I_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_I_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_G_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_G_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_G_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_G_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_G_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_G_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_O_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

def chain_O_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_O_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_O_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_OF_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_OF_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_OF_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_OF_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_OF_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_OF_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_R_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_R_B2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_R_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_R_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_R_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_R_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_I_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_I_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_I_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_I_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_B2_filters4_FORWARD; decide

theorem chain_I_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_B2_filters4_FORWARD "red" "gray" chain_I_B2_filters4_FORWARD_guarded p accepted

def chain_I_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "esp"], .allow⟩]

def chain_I_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_I_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_I_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_G_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_G_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_G_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_G_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_G_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_G_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_R_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_R_A3_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_R_A3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_R_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_R_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_R_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_I_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_I_A3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 103], .allow⟩]

lemma chain_I_A3_filters4_FORWARD_guarded : ∀ r ∈ chain_I_A3_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_A3_filters4_FORWARD; decide

theorem chain_I_A3_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_A3_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_A3_filters4_FORWARD "red" "gray" chain_I_A3_filters4_FORWARD_guarded p accepted

def chain_I_A3_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .egress "gray", .protocol "esp"], .allow⟩]

def chain_I_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_I_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_I_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_G_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_G_A3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_G_A3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_G_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_G_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_G_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_R_B3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_R_B3_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_R_B3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_R_B3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_R_B3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_R_B3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_I_B3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_I_B3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 103], .allow⟩]

lemma chain_I_B3_filters4_FORWARD_guarded : ∀ r ∈ chain_I_B3_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_B3_filters4_FORWARD; decide

theorem chain_I_B3_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_B3_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_B3_filters4_FORWARD "red" "gray" chain_I_B3_filters4_FORWARD_guarded p accepted

def chain_I_B3_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .egress "gray", .protocol "esp"], .allow⟩]

def chain_I_B3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_I_B3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_I_B3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_G_B3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_G_B3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_G_B3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_G_B3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_G_B3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_G_B3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_O_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

def chain_O_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_O_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_O_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_OF_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_OF_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_OF_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_OF_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_OF_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_OF_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_O_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

def chain_O_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_O_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_O_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_OF_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_OF_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_OF_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_OF_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_OF_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_OF_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_GR_A_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_GR_A_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_GR_A_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_GR_A_filters6_INPUT : List PacketPolicy.Rule := []

def chain_GR_A_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_GR_A_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_GR_B_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_GR_B_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_GR_B_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_GR_B_filters6_INPUT : List PacketPolicy.Rule := []

def chain_GR_B_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_GR_B_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_R_A4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_R_A4_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_R_A4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_R_A4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_R_A4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_R_A4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_I_A4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_I_A4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 104], .allow⟩]

lemma chain_I_A4_filters4_FORWARD_guarded : ∀ r ∈ chain_I_A4_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_A4_filters4_FORWARD; decide

theorem chain_I_A4_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_A4_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_A4_filters4_FORWARD "red" "gray" chain_I_A4_filters4_FORWARD_guarded p accepted

def chain_I_A4_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .egress "gray", .protocol "esp"], .allow⟩]

def chain_I_A4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_I_A4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_I_A4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_G_A4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_G_A4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_G_A4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_G_A4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_G_A4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_G_A4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_R_B4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_R_B4_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_R_B4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_R_B4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_R_B4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_R_B4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_I_B4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_I_B4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 104], .allow⟩]

lemma chain_I_B4_filters4_FORWARD_guarded : ∀ r ∈ chain_I_B4_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_B4_filters4_FORWARD; decide

theorem chain_I_B4_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_I_B4_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_I_B4_filters4_FORWARD "red" "gray" chain_I_B4_filters4_FORWARD_guarded p accepted

def chain_I_B4_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .egress "gray", .protocol "esp"], .allow⟩]

def chain_I_B4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_I_B4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_I_B4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_G_B4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_G_B4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_G_B4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_G_B4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_G_B4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_G_B4_filters6_OUTPUT : List PacketPolicy.Rule := []

def observedESPHardLifetimes : List Evidence.HardLifetimeFact := [⟨"I_A1", 0, 3600⟩, ⟨"I_A1", 1, 3600⟩, ⟨"O_A1", 0, 3600⟩, ⟨"O_A1", 1, 3600⟩, ⟨"I_A2", 0, 3600⟩, ⟨"I_A2", 1, 3600⟩, ⟨"I_B1", 0, 3600⟩, ⟨"I_B1", 1, 3600⟩, ⟨"O_B1", 0, 3600⟩, ⟨"O_B1", 1, 3600⟩, ⟨"I_B2", 0, 3600⟩, ⟨"I_B2", 1, 3600⟩, ⟨"I_A3", 0, 3600⟩, ⟨"I_A3", 1, 3600⟩, ⟨"I_B3", 0, 3600⟩, ⟨"I_B3", 1, 3600⟩, ⟨"O_A2", 0, 3600⟩, ⟨"O_A2", 1, 3600⟩, ⟨"O_B2", 0, 3600⟩, ⟨"O_B2", 1, 3600⟩, ⟨"I_A4", 0, 3600⟩, ⟨"I_A4", 1, 3600⟩, ⟨"I_B4", 0, 3600⟩, ⟨"I_B4", 1, 3600⟩]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩, ⟨6, 2, .gcm, .gcm, false⟩, ⟨7, 2, .gcm, .gcm, false⟩, ⟨8, 2, .gcm, .gcm, false⟩, ⟨9, 2, .gcm, .gcm, false⟩, ⟨10, 2, .gcm, .gcm, false⟩, ⟨11, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

def loadedVPNModePolicies : List Targets.VPNModePolicy := [⟨"I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_A3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_A4/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B4/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide

end TDN.Imported.redundant_four_levels_coherent_20261017T2208Z
