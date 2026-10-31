import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.native_baseline_20261017T2237Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def snapshot : Evidence.Snapshot where

  id := "native-baseline-20261017T2237Z"

  manifestSha256 := "ea659989e2b5f45e31576c9fa1285d8d78e19cdbb61c9609bafc1a00f162ac5a"

  snapshotSha256 := "c1796b41b26940acd22555bf6934900dbb8abd78508fd972d4049c774cecb7fe"

  devices := [⟨"NB_BLACK", "transport", none, none, .observed, ["obs-00002", "obs-00081"]⟩, ⟨"NB_GF_A", "gray-firewall", some "A", none, .observed, ["obs-00004", "obs-00100"]⟩, ⟨"NB_R_A1", "host", some "A", some "S1", .observed, ["obs-00006", "obs-00117"]⟩, ⟨"NB_I_A1", "inner", some "A", some "S1", .observed, ["obs-00008", "obs-00129"]⟩, ⟨"NB_G_A1", "switch", some "A", some "S1", .observed, ["obs-00010", "obs-00147"]⟩, ⟨"NB_O_A1", "outer", some "A", some "S1", .observed, ["obs-00012", "obs-00166"]⟩, ⟨"NB_OF_A1", "firewall", some "A", some "S1", .observed, ["obs-00014", "obs-00184"]⟩, ⟨"NB_R_A2", "host", some "A", some "S2", .observed, ["obs-00016", "obs-00203"]⟩, ⟨"NB_I_A2", "inner", some "A", some "S2", .observed, ["obs-00018", "obs-00215"]⟩, ⟨"NB_G_A2", "switch", some "A", some "S2", .observed, ["obs-00020", "obs-00233"]⟩, ⟨"NB_O_A2", "outer", some "A", some "S2", .observed, ["obs-00022", "obs-00252"]⟩, ⟨"NB_OF_A2", "firewall", some "A", some "S2", .observed, ["obs-00024", "obs-00270"]⟩, ⟨"NB_GF_B", "gray-firewall", some "B", none, .observed, ["obs-00026", "obs-00289"]⟩, ⟨"NB_R_B1", "host", some "B", some "S1", .observed, ["obs-00028", "obs-00306"]⟩, ⟨"NB_I_B1", "inner", some "B", some "S1", .observed, ["obs-00030", "obs-00318"]⟩, ⟨"NB_G_B1", "switch", some "B", some "S1", .observed, ["obs-00032", "obs-00336"]⟩, ⟨"NB_O_B1", "outer", some "B", some "S1", .observed, ["obs-00034", "obs-00355"]⟩, ⟨"NB_OF_B1", "firewall", some "B", some "S1", .observed, ["obs-00036", "obs-00373"]⟩, ⟨"NB_R_B2", "host", some "B", some "S2", .observed, ["obs-00038", "obs-00392"]⟩, ⟨"NB_I_B2", "inner", some "B", some "S2", .observed, ["obs-00040", "obs-00404"]⟩, ⟨"NB_G_B2", "switch", some "B", some "S2", .observed, ["obs-00042", "obs-00422"]⟩, ⟨"NB_O_B2", "outer", some "B", some "S2", .observed, ["obs-00044", "obs-00441"]⟩, ⟨"NB_OF_B2", "firewall", some "B", some "S2", .observed, ["obs-00046", "obs-00459"]⟩]

  tunnels := [⟨"NB_I_A1:tunnel", "NB_I_A1", "NB_I_B1", "inner", "IPsec", "tunnel", .observed, ["obs-00131", "obs-00133", "obs-00134", "obs-00135", "obs-00125", "obs-00124"]⟩, ⟨"NB_O_A1:tunnel", "NB_O_A1", "NB_O_B1", "outer", "IPsec", "tunnel", .observed, ["obs-00168", "obs-00170", "obs-00171", "obs-00172", "obs-00162", "obs-00161"]⟩, ⟨"NB_I_A2:tunnel", "NB_I_A2", "NB_I_B2", "inner", "IPsec", "tunnel", .observed, ["obs-00217", "obs-00219", "obs-00220", "obs-00221", "obs-00211", "obs-00210"]⟩, ⟨"NB_O_A2:tunnel", "NB_O_A2", "NB_O_B2", "outer", "IPsec", "tunnel", .observed, ["obs-00254", "obs-00256", "obs-00257", "obs-00258", "obs-00248", "obs-00247"]⟩, ⟨"NB_I_B1:tunnel", "NB_I_B1", "NB_I_A1", "inner", "IPsec", "tunnel", .observed, ["obs-00320", "obs-00322", "obs-00323", "obs-00324", "obs-00314", "obs-00313"]⟩, ⟨"NB_O_B1:tunnel", "NB_O_B1", "NB_O_A1", "outer", "IPsec", "tunnel", .observed, ["obs-00357", "obs-00359", "obs-00360", "obs-00361", "obs-00351", "obs-00350"]⟩, ⟨"NB_I_B2:tunnel", "NB_I_B2", "NB_I_A2", "inner", "IPsec", "tunnel", .observed, ["obs-00406", "obs-00408", "obs-00409", "obs-00410", "obs-00400", "obs-00399"]⟩, ⟨"NB_O_B2:tunnel", "NB_O_B2", "NB_O_A2", "outer", "IPsec", "tunnel", .observed, ["obs-00443", "obs-00445", "obs-00446", "obs-00447", "obs-00437", "obs-00436"]⟩]

  probes := [⟨"probe-obs-00468", "NB_R_A1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00468"]⟩, ⟨"probe-obs-00469", "NB_R_A1", "10.2.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00469"]⟩, ⟨"probe-obs-00470", "NB_R_A1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00470"]⟩, ⟨"probe-obs-00471", "NB_R_A2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00471"]⟩, ⟨"probe-obs-00472", "NB_R_A2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00472"]⟩, ⟨"probe-obs-00473", "NB_R_A2", "10.2.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00473"]⟩, ⟨"probe-obs-00474", "NB_R_B1", "10.1.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00474"]⟩, ⟨"probe-obs-00475", "NB_R_B1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00475"]⟩, ⟨"probe-obs-00476", "NB_R_B1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00476"]⟩, ⟨"probe-obs-00477", "NB_R_B2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00477"]⟩, ⟨"probe-obs-00478", "NB_R_B2", "10.1.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00478"]⟩, ⟨"probe-obs-00479", "NB_R_B2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00479"]⟩]

lemma observed_provenance : Evidence.HasProvenance snapshot := by unfold Evidence.HasProvenance snapshot; decide

theorem useful_observed_traffic : Evidence.HasObservedSuccess snapshot := by unfold Evidence.HasObservedSuccess snapshot; decide

theorem observed_ipsec_tunnel_modes : Evidence.IPsecTunnelModes snapshot := by unfold Evidence.IPsecTunnelModes snapshot; decide

theorem observed_inner_peers_same_declared_level : Evidence.InnerPeersSameDeclaredLevel snapshot := by unfold Evidence.InnerPeersSameDeclaredLevel snapshot; decide

def chain_NB_BLACK_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .ingress "p11", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060481 2887060481, .ingress "p12", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .ingress "p21", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887063041 2887063041, .ingress "p22", .protocol "ospf"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NB_BLACK_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NB_BLACK_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_BLACK_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_BLACK_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_BLACK_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_GF_A_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_NB_GF_A_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NB_GF_A_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_NB_GF_A_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_GF_A_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_GF_A_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_R_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NB_R_A1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NB_R_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_R_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_R_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_R_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_I_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NB_I_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_NB_I_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_NB_I_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NB_I_A1_filters4_FORWARD; decide

theorem chain_NB_I_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NB_I_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NB_I_A1_filters4_FORWARD "red" "gray" chain_NB_I_A1_filters4_FORWARD_guarded p accepted

def chain_NB_I_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NB_I_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_I_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_I_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_G_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NB_G_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NB_G_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_G_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_G_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_G_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_O_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NB_O_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

lemma chain_NB_O_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_NB_O_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_NB_O_A1_filters4_FORWARD; decide

theorem chain_NB_O_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NB_O_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_NB_O_A1_filters4_FORWARD "gray" "black" chain_NB_O_A1_filters4_FORWARD_guarded p accepted

def chain_NB_O_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NB_O_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_O_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_O_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_OF_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 2887060225 2887060225, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NB_OF_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NB_OF_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 2887060226 2887060226, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NB_OF_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_OF_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_OF_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_R_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NB_R_A2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NB_R_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_R_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_R_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_R_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_I_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NB_I_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_NB_I_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_NB_I_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NB_I_A2_filters4_FORWARD; decide

theorem chain_NB_I_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NB_I_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NB_I_A2_filters4_FORWARD "red" "gray" chain_NB_I_A2_filters4_FORWARD_guarded p accepted

def chain_NB_I_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NB_I_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_I_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_I_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_G_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NB_G_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NB_G_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_G_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_G_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_G_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_O_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NB_O_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

lemma chain_NB_O_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_NB_O_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_NB_O_A2_filters4_FORWARD; decide

theorem chain_NB_O_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NB_O_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_NB_O_A2_filters4_FORWARD "gray" "black" chain_NB_O_A2_filters4_FORWARD_guarded p accepted

def chain_NB_O_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NB_O_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_O_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_O_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_OF_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060482 2887060482, .destinationRange 2887060481 2887060481, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060482 2887060482, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NB_OF_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NB_OF_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887060481 2887060481, .destinationRange 2887060482 2887060482, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060481 2887060481, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NB_OF_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_OF_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_OF_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_GF_B_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_NB_GF_B_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NB_GF_B_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_NB_GF_B_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_GF_B_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_GF_B_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_R_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NB_R_B1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NB_R_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_R_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_R_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_R_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_I_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NB_I_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_NB_I_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_NB_I_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NB_I_B1_filters4_FORWARD; decide

theorem chain_NB_I_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NB_I_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NB_I_B1_filters4_FORWARD "red" "gray" chain_NB_I_B1_filters4_FORWARD_guarded p accepted

def chain_NB_I_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NB_I_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_I_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_I_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_G_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NB_G_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NB_G_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_G_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_G_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_G_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_O_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NB_O_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

lemma chain_NB_O_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_NB_O_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_NB_O_B1_filters4_FORWARD; decide

theorem chain_NB_O_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NB_O_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_NB_O_B1_filters4_FORWARD "gray" "black" chain_NB_O_B1_filters4_FORWARD_guarded p accepted

def chain_NB_O_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NB_O_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_O_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_O_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_OF_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 2887062785 2887062785, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NB_OF_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NB_OF_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 2887062786 2887062786, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NB_OF_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_OF_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_OF_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_R_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NB_R_B2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NB_R_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_R_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_R_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_R_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_I_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NB_I_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_NB_I_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_NB_I_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NB_I_B2_filters4_FORWARD; decide

theorem chain_NB_I_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NB_I_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NB_I_B2_filters4_FORWARD "red" "gray" chain_NB_I_B2_filters4_FORWARD_guarded p accepted

def chain_NB_I_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NB_I_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_I_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_I_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_G_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NB_G_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NB_G_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_G_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_G_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_G_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_O_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NB_O_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

lemma chain_NB_O_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_NB_O_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_NB_O_B2_filters4_FORWARD; decide

theorem chain_NB_O_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NB_O_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_NB_O_B2_filters4_FORWARD "gray" "black" chain_NB_O_B2_filters4_FORWARD_guarded p accepted

def chain_NB_O_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NB_O_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_O_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_O_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NB_OF_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887063042 2887063042, .destinationRange 2887063041 2887063041, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887063042 2887063042, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NB_OF_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NB_OF_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887063041 2887063041, .destinationRange 2887063042 2887063042, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887063041 2887063041, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NB_OF_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NB_OF_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NB_OF_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def observedESPHardLifetimes : List Evidence.HardLifetimeFact := [⟨"NB_I_A1", 0, 3600⟩, ⟨"NB_I_A1", 1, 3600⟩, ⟨"NB_O_A1", 0, 3600⟩, ⟨"NB_O_A1", 1, 3600⟩, ⟨"NB_I_A2", 0, 3600⟩, ⟨"NB_I_A2", 1, 3600⟩, ⟨"NB_O_A2", 0, 3600⟩, ⟨"NB_O_A2", 1, 3600⟩, ⟨"NB_I_B1", 0, 3600⟩, ⟨"NB_I_B1", 1, 3600⟩, ⟨"NB_O_B1", 0, 3600⟩, ⟨"NB_O_B1", 1, 3600⟩, ⟨"NB_I_B2", 0, 3600⟩, ⟨"NB_I_B2", 1, 3600⟩, ⟨"NB_O_B2", 0, 3600⟩, ⟨"NB_O_B2", 1, 3600⟩]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩, ⟨6, 2, .gcm, .gcm, false⟩, ⟨7, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

def loadedVPNModePolicies : List Targets.VPNModePolicy := [⟨"NB_I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_O_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_O_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide

end TDN.Imported.native_baseline_20261017T2237Z
