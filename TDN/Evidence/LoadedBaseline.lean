import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.baseline_loaded_20261017T2117Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def snapshot : Evidence.Snapshot where

  id := "baseline-loaded-20261017T2117Z"

  manifestSha256 := "013821e34d733ea44a771dff41727865b5df9769e0974d1505de3d4f2bf19b68"

  snapshotSha256 := "094311c7a1c72e7ec4d322d3949b8ca7c9f357545983a5125cbeb6ae6b16b8f7"

  devices := [⟨"BLACK", "transport", none, none, .observed, ["obs-00002", "obs-00081"]⟩, ⟨"GF_A", "gray-firewall", some "A", none, .observed, ["obs-00004", "obs-00093"]⟩, ⟨"R_A1", "host", some "A", some "S1", .observed, ["obs-00006", "obs-00105"]⟩, ⟨"I_A1", "inner", some "A", some "S1", .observed, ["obs-00008", "obs-00117"]⟩, ⟨"G_A1", "switch", some "A", some "S1", .observed, ["obs-00010", "obs-00135"]⟩, ⟨"O_A1", "outer", some "A", some "S1", .observed, ["obs-00012", "obs-00147"]⟩, ⟨"OF_A1", "firewall", some "A", some "S1", .observed, ["obs-00014", "obs-00165"]⟩, ⟨"R_A2", "host", some "A", some "S2", .observed, ["obs-00016", "obs-00177"]⟩, ⟨"I_A2", "inner", some "A", some "S2", .observed, ["obs-00018", "obs-00189"]⟩, ⟨"G_A2", "switch", some "A", some "S2", .observed, ["obs-00020", "obs-00207"]⟩, ⟨"O_A2", "outer", some "A", some "S2", .observed, ["obs-00022", "obs-00219"]⟩, ⟨"OF_A2", "firewall", some "A", some "S2", .observed, ["obs-00024", "obs-00237"]⟩, ⟨"GF_B", "gray-firewall", some "B", none, .observed, ["obs-00026", "obs-00249"]⟩, ⟨"R_B1", "host", some "B", some "S1", .observed, ["obs-00028", "obs-00261"]⟩, ⟨"I_B1", "inner", some "B", some "S1", .observed, ["obs-00030", "obs-00273"]⟩, ⟨"G_B1", "switch", some "B", some "S1", .observed, ["obs-00032", "obs-00291"]⟩, ⟨"O_B1", "outer", some "B", some "S1", .observed, ["obs-00034", "obs-00303"]⟩, ⟨"OF_B1", "firewall", some "B", some "S1", .observed, ["obs-00036", "obs-00321"]⟩, ⟨"R_B2", "host", some "B", some "S2", .observed, ["obs-00038", "obs-00333"]⟩, ⟨"I_B2", "inner", some "B", some "S2", .observed, ["obs-00040", "obs-00345"]⟩, ⟨"G_B2", "switch", some "B", some "S2", .observed, ["obs-00042", "obs-00363"]⟩, ⟨"O_B2", "outer", some "B", some "S2", .observed, ["obs-00044", "obs-00375"]⟩, ⟨"OF_B2", "firewall", some "B", some "S2", .observed, ["obs-00046", "obs-00393"]⟩]

  tunnels := [⟨"I_A1:tunnel", "I_A1", "I_B1", "inner", "IPsec", "tunnel", .observed, ["obs-00119", "obs-00121", "obs-00122", "obs-00123", "obs-00113", "obs-00112"]⟩, ⟨"O_A1:tunnel", "O_A1", "O_B1", "outer", "IPsec", "tunnel", .observed, ["obs-00149", "obs-00151", "obs-00152", "obs-00153", "obs-00143", "obs-00142"]⟩, ⟨"I_A2:tunnel", "I_A2", "I_B2", "inner", "IPsec", "tunnel", .observed, ["obs-00191", "obs-00193", "obs-00194", "obs-00195", "obs-00185", "obs-00184"]⟩, ⟨"O_A2:tunnel", "O_A2", "O_B2", "outer", "IPsec", "tunnel", .observed, ["obs-00221", "obs-00223", "obs-00224", "obs-00225", "obs-00215", "obs-00214"]⟩, ⟨"I_B1:tunnel", "I_B1", "I_A1", "inner", "IPsec", "tunnel", .observed, ["obs-00275", "obs-00277", "obs-00278", "obs-00279", "obs-00269", "obs-00268"]⟩, ⟨"O_B1:tunnel", "O_B1", "O_A1", "outer", "IPsec", "tunnel", .observed, ["obs-00305", "obs-00307", "obs-00308", "obs-00309", "obs-00299", "obs-00298"]⟩, ⟨"I_B2:tunnel", "I_B2", "I_A2", "inner", "IPsec", "tunnel", .observed, ["obs-00347", "obs-00349", "obs-00350", "obs-00351", "obs-00341", "obs-00340"]⟩, ⟨"O_B2:tunnel", "O_B2", "O_A2", "outer", "IPsec", "tunnel", .observed, ["obs-00377", "obs-00379", "obs-00380", "obs-00381", "obs-00371", "obs-00370"]⟩]

  probes := [⟨"probe-obs-00395", "R_A1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00395"]⟩, ⟨"probe-obs-00396", "R_A1", "10.2.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00396"]⟩, ⟨"probe-obs-00397", "R_A1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00397"]⟩, ⟨"probe-obs-00398", "R_A2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00398"]⟩, ⟨"probe-obs-00399", "R_A2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00399"]⟩, ⟨"probe-obs-00400", "R_A2", "10.2.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00400"]⟩, ⟨"probe-obs-00401", "R_B1", "10.1.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00401"]⟩, ⟨"probe-obs-00402", "R_B1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00402"]⟩, ⟨"probe-obs-00403", "R_B1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00403"]⟩, ⟨"probe-obs-00404", "R_B2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00404"]⟩, ⟨"probe-obs-00405", "R_B2", "10.1.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00405"]⟩, ⟨"probe-obs-00406", "R_B2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00406"]⟩]

theorem observed_provenance : Evidence.HasProvenance snapshot := by unfold Evidence.HasProvenance snapshot; decide

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

theorem chain_I_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_I_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_A1_filters4_FORWARD; decide

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

def chain_O_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

theorem chain_O_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_O_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_O_A1_filters4_FORWARD; decide

theorem chain_O_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_O_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_O_A1_filters4_FORWARD "gray" "black" chain_O_A1_filters4_FORWARD_guarded p accepted

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

theorem chain_I_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_I_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_A2_filters4_FORWARD; decide

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

def chain_O_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

theorem chain_O_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_O_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_O_A2_filters4_FORWARD; decide

theorem chain_O_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_O_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_O_A2_filters4_FORWARD "gray" "black" chain_O_A2_filters4_FORWARD_guarded p accepted

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

theorem chain_I_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_I_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_B1_filters4_FORWARD; decide

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

def chain_O_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

theorem chain_O_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_O_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_O_B1_filters4_FORWARD; decide

theorem chain_O_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_O_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_O_B1_filters4_FORWARD "gray" "black" chain_O_B1_filters4_FORWARD_guarded p accepted

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

theorem chain_I_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_I_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_B2_filters4_FORWARD; decide

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

def chain_O_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_O_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

theorem chain_O_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_O_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_O_B2_filters4_FORWARD; decide

theorem chain_O_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_O_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_O_B2_filters4_FORWARD "gray" "black" chain_O_B2_filters4_FORWARD_guarded p accepted

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

def observedESPHardLifetimes : List Evidence.HardLifetimeFact := [⟨"I_A1", 0, 3600⟩, ⟨"I_A1", 1, 3600⟩, ⟨"O_A1", 0, 3600⟩, ⟨"O_A1", 1, 3600⟩, ⟨"I_A2", 0, 3600⟩, ⟨"I_A2", 1, 3600⟩, ⟨"O_A2", 0, 3600⟩, ⟨"O_A2", 1, 3600⟩, ⟨"I_B1", 0, 3600⟩, ⟨"I_B1", 1, 3600⟩, ⟨"O_B1", 0, 3600⟩, ⟨"O_B1", 1, 3600⟩, ⟨"I_B2", 0, 3600⟩, ⟨"I_B2", 1, 3600⟩, ⟨"O_B2", 0, 3600⟩, ⟨"O_B2", 1, 3600⟩]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩, ⟨6, 2, .gcm, .gcm, false⟩, ⟨7, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

def loadedVPNModePolicies : List Targets.VPNModePolicy := [⟨"I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide

end TDN.Imported.baseline_loaded_20261017T2117Z
