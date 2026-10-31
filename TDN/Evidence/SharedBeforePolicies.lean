import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.shared_three_level_20261017T2117Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def snapshot : Evidence.Snapshot where

  id := "shared-three-level-20261017T2117Z"

  manifestSha256 := "d417163785e8e0009a772befa9c473f6a7e33557b631b877b05c6cce5f8d68e8"

  snapshotSha256 := "a7c33d1095778b9de6c323ef946a726d3ef5f25a263d27fbe5463cfe3d39c893"

  devices := [⟨"BLACK", "transport", none, none, .observed, ["obs-00002", "obs-00087"]⟩, ⟨"GF_A", "gray-firewall", some "A", none, .observed, ["obs-00004", "obs-00099"]⟩, ⟨"R_A1", "host", some "A", some "S1", .observed, ["obs-00006", "obs-00111"]⟩, ⟨"I_A1", "inner", some "A", some "S1", .observed, ["obs-00008", "obs-00123"]⟩, ⟨"G_A1", "switch", some "A", some "S1", .observed, ["obs-00010", "obs-00141"]⟩, ⟨"O_A1", "outer", some "A", some "shared", .observed, ["obs-00012", "obs-00153"]⟩, ⟨"OF_A1", "firewall", some "A", some "S1", .observed, ["obs-00014", "obs-00171"]⟩, ⟨"R_A2", "host", some "A", some "S2", .observed, ["obs-00016", "obs-00183"]⟩, ⟨"I_A2", "inner", some "A", some "S2", .observed, ["obs-00018", "obs-00195"]⟩, ⟨"G_A2", "switch", some "A", some "S2", .observed, ["obs-00020", "obs-00213"]⟩, ⟨"GF_B", "gray-firewall", some "B", none, .observed, ["obs-00022", "obs-00225"]⟩, ⟨"R_B1", "host", some "B", some "S1", .observed, ["obs-00024", "obs-00237"]⟩, ⟨"I_B1", "inner", some "B", some "S1", .observed, ["obs-00026", "obs-00249"]⟩, ⟨"G_B1", "switch", some "B", some "S1", .observed, ["obs-00028", "obs-00267"]⟩, ⟨"O_B1", "outer", some "B", some "shared", .observed, ["obs-00030", "obs-00279"]⟩, ⟨"OF_B1", "firewall", some "B", some "S1", .observed, ["obs-00032", "obs-00297"]⟩, ⟨"R_B2", "host", some "B", some "S2", .observed, ["obs-00034", "obs-00309"]⟩, ⟨"I_B2", "inner", some "B", some "S2", .observed, ["obs-00036", "obs-00321"]⟩, ⟨"G_B2", "switch", some "B", some "S2", .observed, ["obs-00038", "obs-00339"]⟩, ⟨"R_A3", "host", some "A", some "UNCLASSIFIED", .observed, ["obs-00040", "obs-00351"]⟩, ⟨"I_A3", "inner", some "A", some "UNCLASSIFIED", .observed, ["obs-00042", "obs-00363"]⟩, ⟨"G_A3", "switch", some "A", some "UNCLASSIFIED", .observed, ["obs-00044", "obs-00381"]⟩, ⟨"R_B3", "host", some "B", some "UNCLASSIFIED", .observed, ["obs-00046", "obs-00393"]⟩, ⟨"I_B3", "inner", some "B", some "UNCLASSIFIED", .observed, ["obs-00048", "obs-00405"]⟩, ⟨"G_B3", "switch", some "B", some "UNCLASSIFIED", .observed, ["obs-00050", "obs-00423"]⟩]

  tunnels := [⟨"I_A1:tunnel", "I_A1", "I_B1", "inner", "IPsec", "tunnel", .observed, ["obs-00125", "obs-00127", "obs-00128", "obs-00129", "obs-00119", "obs-00118"]⟩, ⟨"O_A1:tunnel", "O_A1", "O_B1", "outer", "IPsec", "tunnel", .observed, ["obs-00155", "obs-00157", "obs-00158", "obs-00159", "obs-00149", "obs-00148"]⟩, ⟨"I_A2:tunnel", "I_A2", "I_B2", "inner", "IPsec", "tunnel", .observed, ["obs-00197", "obs-00199", "obs-00200", "obs-00201", "obs-00191", "obs-00190"]⟩, ⟨"I_B1:tunnel", "I_B1", "I_A1", "inner", "IPsec", "tunnel", .observed, ["obs-00251", "obs-00253", "obs-00254", "obs-00255", "obs-00245", "obs-00244"]⟩, ⟨"O_B1:tunnel", "O_B1", "O_A1", "outer", "IPsec", "tunnel", .observed, ["obs-00281", "obs-00283", "obs-00284", "obs-00285", "obs-00275", "obs-00274"]⟩, ⟨"I_B2:tunnel", "I_B2", "I_A2", "inner", "IPsec", "tunnel", .observed, ["obs-00323", "obs-00325", "obs-00326", "obs-00327", "obs-00317", "obs-00316"]⟩, ⟨"I_A3:tunnel", "I_A3", "I_B3", "inner", "IPsec", "tunnel", .observed, ["obs-00365", "obs-00367", "obs-00368", "obs-00369", "obs-00359", "obs-00358"]⟩, ⟨"I_B3:tunnel", "I_B3", "I_A3", "inner", "IPsec", "tunnel", .observed, ["obs-00407", "obs-00409", "obs-00410", "obs-00411", "obs-00401", "obs-00400"]⟩]

  probes := [⟨"probe-obs-00425", "R_A1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00425"]⟩, ⟨"probe-obs-00426", "R_A1", "10.2.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00426"]⟩, ⟨"probe-obs-00427", "R_A1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00427"]⟩, ⟨"probe-obs-00428", "R_A1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00428"]⟩, ⟨"probe-obs-00429", "R_A1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00429"]⟩, ⟨"probe-obs-00430", "R_A2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00430"]⟩, ⟨"probe-obs-00431", "R_A2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00431"]⟩, ⟨"probe-obs-00432", "R_A2", "10.2.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00432"]⟩, ⟨"probe-obs-00433", "R_A2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00433"]⟩, ⟨"probe-obs-00434", "R_A2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00434"]⟩, ⟨"probe-obs-00435", "R_B1", "10.1.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00435"]⟩, ⟨"probe-obs-00436", "R_B1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00436"]⟩, ⟨"probe-obs-00437", "R_B1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00437"]⟩, ⟨"probe-obs-00438", "R_B1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00438"]⟩, ⟨"probe-obs-00439", "R_B1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00439"]⟩, ⟨"probe-obs-00440", "R_B2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00440"]⟩, ⟨"probe-obs-00441", "R_B2", "10.1.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00441"]⟩, ⟨"probe-obs-00442", "R_B2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00442"]⟩, ⟨"probe-obs-00443", "R_B2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00443"]⟩, ⟨"probe-obs-00444", "R_B2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00444"]⟩, ⟨"probe-obs-00445", "R_A3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00445"]⟩, ⟨"probe-obs-00446", "R_A3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00446"]⟩, ⟨"probe-obs-00447", "R_A3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00447"]⟩, ⟨"probe-obs-00448", "R_A3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00448"]⟩, ⟨"probe-obs-00449", "R_A3", "10.2.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00449"]⟩, ⟨"probe-obs-00450", "R_B3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00450"]⟩, ⟨"probe-obs-00451", "R_B3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00451"]⟩, ⟨"probe-obs-00452", "R_B3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00452"]⟩, ⟨"probe-obs-00453", "R_B3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00453"]⟩, ⟨"probe-obs-00454", "R_B3", "10.1.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00454"]⟩]

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

def chain_GF_A_filters4_FORWARD : List PacketPolicy.Rule := []

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

def chain_O_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

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

def chain_GF_B_filters4_FORWARD : List PacketPolicy.Rule := []

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

def chain_O_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

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

def observedESPHardLifetimes : List Evidence.HardLifetimeFact := [⟨"I_A1", 0, 3600⟩, ⟨"I_A1", 1, 3600⟩, ⟨"O_A1", 0, 3600⟩, ⟨"O_A1", 1, 3600⟩, ⟨"I_A2", 0, 3600⟩, ⟨"I_A2", 1, 3600⟩, ⟨"I_B1", 0, 3600⟩, ⟨"I_B1", 1, 3600⟩, ⟨"O_B1", 0, 3600⟩, ⟨"O_B1", 1, 3600⟩, ⟨"I_B2", 0, 3600⟩, ⟨"I_B2", 1, 3600⟩, ⟨"I_A3", 0, 3600⟩, ⟨"I_A3", 1, 3600⟩, ⟨"I_B3", 0, 3600⟩, ⟨"I_B3", 1, 3600⟩]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩, ⟨6, 2, .gcm, .gcm, false⟩, ⟨7, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

def loadedVPNModePolicies : List Targets.VPNModePolicy := [⟨"I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_A3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide

end TDN.Imported.shared_three_level_20261017T2117Z
