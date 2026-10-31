import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.native_samelevel_20261017T2242Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def snapshot : Evidence.Snapshot where

  id := "native-samelevel-20261017T2242Z"

  manifestSha256 := "07cc06f35a9fdc5c37ed92c05fd6947f7eb0a62cd26e28a690200d97e204940e"

  snapshotSha256 := "a46130111585ee8ade92ee79b1956a1dfae286c677467fdcc79f37635b025715"

  devices := [⟨"NT_BLACK", "transport", none, none, .observed, ["obs-00002", "obs-00069"]⟩, ⟨"NT_GF_A", "gray-firewall", some "A", none, .observed, ["obs-00004", "obs-00088"]⟩, ⟨"NT_R_A1", "host", some "A", some "SECRET-US-only", .observed, ["obs-00006", "obs-00105"]⟩, ⟨"NT_I_A1", "inner", some "A", some "SECRET-US-only", .observed, ["obs-00008", "obs-00117"]⟩, ⟨"NT_G_A1", "switch", some "A", some "SECRET-US-only", .observed, ["obs-00010", "obs-00135"]⟩, ⟨"NT_O_A1", "outer", some "A", some "shared", .observed, ["obs-00012", "obs-00154"]⟩, ⟨"NT_OF_A1", "firewall", some "A", some "SECRET-US-only", .observed, ["obs-00014", "obs-00172"]⟩, ⟨"NT_R_A2", "host", some "A", some "SECRET-US-only", .observed, ["obs-00016", "obs-00191"]⟩, ⟨"NT_I_A2", "inner", some "A", some "SECRET-US-only", .observed, ["obs-00018", "obs-00203"]⟩, ⟨"NT_G_A2", "switch", some "A", some "SECRET-US-only", .observed, ["obs-00020", "obs-00221"]⟩, ⟨"NT_GF_B", "gray-firewall", some "B", none, .observed, ["obs-00022", "obs-00240"]⟩, ⟨"NT_R_B1", "host", some "B", some "SECRET-US-only", .observed, ["obs-00024", "obs-00257"]⟩, ⟨"NT_I_B1", "inner", some "B", some "SECRET-US-only", .observed, ["obs-00026", "obs-00269"]⟩, ⟨"NT_G_B1", "switch", some "B", some "SECRET-US-only", .observed, ["obs-00028", "obs-00287"]⟩, ⟨"NT_O_B1", "outer", some "B", some "shared", .observed, ["obs-00030", "obs-00306"]⟩, ⟨"NT_OF_B1", "firewall", some "B", some "SECRET-US-only", .observed, ["obs-00032", "obs-00324"]⟩, ⟨"NT_R_B2", "host", some "B", some "SECRET-US-only", .observed, ["obs-00034", "obs-00343"]⟩, ⟨"NT_I_B2", "inner", some "B", some "SECRET-US-only", .observed, ["obs-00036", "obs-00355"]⟩, ⟨"NT_G_B2", "switch", some "B", some "SECRET-US-only", .observed, ["obs-00038", "obs-00373"]⟩]

  tunnels := [⟨"NT_I_A1:tunnel", "NT_I_A1", "NT_I_B1", "inner", "IPsec", "tunnel", .observed, ["obs-00119", "obs-00121", "obs-00122", "obs-00123", "obs-00113", "obs-00112"]⟩, ⟨"NT_O_A1:tunnel", "NT_O_A1", "NT_O_B1", "outer", "IPsec", "tunnel", .observed, ["obs-00156", "obs-00158", "obs-00159", "obs-00160", "obs-00150", "obs-00149"]⟩, ⟨"NT_I_A2:tunnel", "NT_I_A2", "NT_I_B2", "inner", "IPsec", "tunnel", .observed, ["obs-00205", "obs-00207", "obs-00208", "obs-00209", "obs-00199", "obs-00198"]⟩, ⟨"NT_I_B1:tunnel", "NT_I_B1", "NT_I_A1", "inner", "IPsec", "tunnel", .observed, ["obs-00271", "obs-00273", "obs-00274", "obs-00275", "obs-00265", "obs-00264"]⟩, ⟨"NT_O_B1:tunnel", "NT_O_B1", "NT_O_A1", "outer", "IPsec", "tunnel", .observed, ["obs-00308", "obs-00310", "obs-00311", "obs-00312", "obs-00302", "obs-00301"]⟩, ⟨"NT_I_B2:tunnel", "NT_I_B2", "NT_I_A2", "inner", "IPsec", "tunnel", .observed, ["obs-00357", "obs-00359", "obs-00360", "obs-00361", "obs-00351", "obs-00350"]⟩]

  probes := [⟨"probe-obs-00382", "NT_R_A1", "10.1.2.10", "cross-network denial", "no_reply", .observed, ["obs-00382"]⟩, ⟨"probe-obs-00383", "NT_R_A1", "10.2.1.10", "within-network useful traffic", "delivered", .observed, ["obs-00383"]⟩, ⟨"probe-obs-00384", "NT_R_A1", "10.2.2.10", "cross-network denial", "no_reply", .observed, ["obs-00384"]⟩, ⟨"probe-obs-00385", "NT_R_A2", "10.1.1.10", "cross-network denial", "no_reply", .observed, ["obs-00385"]⟩, ⟨"probe-obs-00386", "NT_R_A2", "10.2.1.10", "cross-network denial", "no_reply", .observed, ["obs-00386"]⟩, ⟨"probe-obs-00387", "NT_R_A2", "10.2.2.10", "within-network useful traffic", "delivered", .observed, ["obs-00387"]⟩, ⟨"probe-obs-00388", "NT_R_B1", "10.1.1.10", "within-network useful traffic", "delivered", .observed, ["obs-00388"]⟩, ⟨"probe-obs-00389", "NT_R_B1", "10.1.2.10", "cross-network denial", "no_reply", .observed, ["obs-00389"]⟩, ⟨"probe-obs-00390", "NT_R_B1", "10.2.2.10", "cross-network denial", "no_reply", .observed, ["obs-00390"]⟩, ⟨"probe-obs-00391", "NT_R_B2", "10.1.1.10", "cross-network denial", "no_reply", .observed, ["obs-00391"]⟩, ⟨"probe-obs-00392", "NT_R_B2", "10.1.2.10", "within-network useful traffic", "delivered", .observed, ["obs-00392"]⟩, ⟨"probe-obs-00393", "NT_R_B2", "10.2.1.10", "cross-network denial", "no_reply", .observed, ["obs-00393"]⟩]

theorem observed_provenance : Evidence.HasProvenance snapshot := by unfold Evidence.HasProvenance snapshot; decide

theorem useful_observed_traffic : Evidence.HasObservedSuccess snapshot := by unfold Evidence.HasObservedSuccess snapshot; decide

theorem observed_ipsec_tunnel_modes : Evidence.IPsecTunnelModes snapshot := by unfold Evidence.IPsecTunnelModes snapshot; decide

theorem observed_inner_peers_same_declared_level : Evidence.InnerPeersSameDeclaredLevel snapshot := by unfold Evidence.InnerPeersSameDeclaredLevel snapshot; decide

def chain_NT_BLACK_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .ingress "p11", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .ingress "p21", .protocol "ospf"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NT_BLACK_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NT_BLACK_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_BLACK_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_BLACK_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_BLACK_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_GF_A_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_NT_GF_A_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NT_GF_A_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_NT_GF_A_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_GF_A_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_GF_A_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_R_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NT_R_A1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NT_R_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_R_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_R_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_R_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_I_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NT_I_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

theorem chain_NT_I_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_NT_I_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NT_I_A1_filters4_FORWARD; decide

theorem chain_NT_I_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NT_I_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NT_I_A1_filters4_FORWARD "red" "gray" chain_NT_I_A1_filters4_FORWARD_guarded p accepted

def chain_NT_I_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NT_I_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_I_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_I_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_G_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NT_G_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NT_G_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_G_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_G_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_G_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_O_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NT_O_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

def chain_NT_O_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NT_O_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_O_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_O_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_OF_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 2887060225 2887060225, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NT_OF_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NT_OF_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 2887060226 2887060226, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NT_OF_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_OF_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_OF_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_R_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NT_R_A2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NT_R_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_R_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_R_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_R_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_I_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NT_I_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

theorem chain_NT_I_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_NT_I_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NT_I_A2_filters4_FORWARD; decide

theorem chain_NT_I_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NT_I_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NT_I_A2_filters4_FORWARD "red" "gray" chain_NT_I_A2_filters4_FORWARD_guarded p accepted

def chain_NT_I_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NT_I_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_I_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_I_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_G_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NT_G_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NT_G_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_G_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_G_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_G_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_GF_B_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_NT_GF_B_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NT_GF_B_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_NT_GF_B_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_GF_B_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_GF_B_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_R_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NT_R_B1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NT_R_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_R_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_R_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_R_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_I_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NT_I_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

theorem chain_NT_I_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_NT_I_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NT_I_B1_filters4_FORWARD; decide

theorem chain_NT_I_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NT_I_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NT_I_B1_filters4_FORWARD "red" "gray" chain_NT_I_B1_filters4_FORWARD_guarded p accepted

def chain_NT_I_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NT_I_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_I_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_I_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_G_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NT_G_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NT_G_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_G_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_G_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_G_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_O_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NT_O_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

def chain_NT_O_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NT_O_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_O_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_O_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_OF_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 2887062785 2887062785, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NT_OF_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NT_OF_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 2887062786 2887062786, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NT_OF_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_OF_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_OF_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_R_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NT_R_B2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NT_R_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_R_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_R_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_R_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_I_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NT_I_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

theorem chain_NT_I_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_NT_I_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NT_I_B2_filters4_FORWARD; decide

theorem chain_NT_I_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NT_I_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NT_I_B2_filters4_FORWARD "red" "gray" chain_NT_I_B2_filters4_FORWARD_guarded p accepted

def chain_NT_I_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NT_I_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_I_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_I_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_G_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NT_G_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NT_G_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NT_G_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NT_G_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NT_G_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def observedESPHardLifetimes : List Evidence.HardLifetimeFact := [⟨"NT_I_A1", 0, 3600⟩, ⟨"NT_I_A1", 1, 3600⟩, ⟨"NT_O_A1", 0, 3600⟩, ⟨"NT_O_A1", 1, 3600⟩, ⟨"NT_I_A2", 0, 3600⟩, ⟨"NT_I_A2", 1, 3600⟩, ⟨"NT_I_B1", 0, 3600⟩, ⟨"NT_I_B1", 1, 3600⟩, ⟨"NT_O_B1", 0, 3600⟩, ⟨"NT_O_B1", 1, 3600⟩, ⟨"NT_I_B2", 0, 3600⟩, ⟨"NT_I_B2", 1, 3600⟩]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

def loadedVPNModePolicies : List Targets.VPNModePolicy := [⟨"NT_I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NT_O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NT_I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NT_I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NT_O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NT_I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide

end TDN.Imported.native_samelevel_20261017T2242Z
