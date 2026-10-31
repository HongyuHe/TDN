import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.redundant_router_coherent_20261017T2149Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def snapshot : Evidence.Snapshot where

  id := "redundant-router-coherent-20261017T2149Z"

  manifestSha256 := "c615db1fe9132c1b01e00d48f2a4a7c6388c3775b564610054a3c577f7934d25"

  snapshotSha256 := "306ec19a91247738f3e75d5cf16843a01ad2aefd5697a2c08d44fd6eb2801bcc"

  devices := [⟨"BLACK", "transport", none, none, .observed, ["obs-00002", "obs-00105"]⟩, ⟨"GF_A", "gray-firewall", some "A", none, .observed, ["obs-00004", "obs-00117"]⟩, ⟨"R_A1", "host", some "A", some "S1", .observed, ["obs-00006", "obs-00129"]⟩, ⟨"I_A1", "inner", some "A", some "S1", .observed, ["obs-00008", "obs-00141"]⟩, ⟨"G_A1", "switch", some "A", some "S1", .observed, ["obs-00010", "obs-00159"]⟩, ⟨"O_A1", "outer", some "A", some "shared", .observed, ["obs-00012", "obs-00171"]⟩, ⟨"OF_A1", "firewall", some "A", some "S1", .observed, ["obs-00014", "obs-00189"]⟩, ⟨"R_A2", "host", some "A", some "S2", .observed, ["obs-00016", "obs-00201"]⟩, ⟨"I_A2", "inner", some "A", some "S2", .observed, ["obs-00018", "obs-00213"]⟩, ⟨"G_A2", "switch", some "A", some "S2", .observed, ["obs-00020", "obs-00231"]⟩, ⟨"GF_B", "gray-firewall", some "B", none, .observed, ["obs-00022", "obs-00243"]⟩, ⟨"R_B1", "host", some "B", some "S1", .observed, ["obs-00024", "obs-00255"]⟩, ⟨"I_B1", "inner", some "B", some "S1", .observed, ["obs-00026", "obs-00267"]⟩, ⟨"G_B1", "switch", some "B", some "S1", .observed, ["obs-00028", "obs-00285"]⟩, ⟨"O_B1", "outer", some "B", some "shared", .observed, ["obs-00030", "obs-00297"]⟩, ⟨"OF_B1", "firewall", some "B", some "S1", .observed, ["obs-00032", "obs-00315"]⟩, ⟨"R_B2", "host", some "B", some "S2", .observed, ["obs-00034", "obs-00327"]⟩, ⟨"I_B2", "inner", some "B", some "S2", .observed, ["obs-00036", "obs-00339"]⟩, ⟨"G_B2", "switch", some "B", some "S2", .observed, ["obs-00038", "obs-00357"]⟩, ⟨"R_A3", "host", some "A", some "UNCLASSIFIED", .observed, ["obs-00040", "obs-00369"]⟩, ⟨"I_A3", "inner", some "A", some "UNCLASSIFIED", .observed, ["obs-00042", "obs-00381"]⟩, ⟨"G_A3", "switch", some "A", some "UNCLASSIFIED", .observed, ["obs-00044", "obs-00399"]⟩, ⟨"R_B3", "host", some "B", some "UNCLASSIFIED", .observed, ["obs-00046", "obs-00411"]⟩, ⟨"I_B3", "inner", some "B", some "UNCLASSIFIED", .observed, ["obs-00048", "obs-00423"]⟩, ⟨"G_B3", "switch", some "B", some "UNCLASSIFIED", .observed, ["obs-00050", "obs-00441"]⟩, ⟨"O_A2", "outer", some "A", some "shared", .observed, ["obs-00052", "obs-00453"]⟩, ⟨"OF_A2", "firewall", some "A", some "S2", .observed, ["obs-00054", "obs-00471"]⟩, ⟨"O_B2", "outer", some "B", some "shared", .observed, ["obs-00056", "obs-00483"]⟩, ⟨"OF_B2", "firewall", some "B", some "S2", .observed, ["obs-00058", "obs-00501"]⟩, ⟨"GR_A", "transport", some "A", none, .observed, ["obs-00060", "obs-00513"]⟩, ⟨"GR_B", "transport", some "B", none, .observed, ["obs-00062", "obs-00525"]⟩]

  tunnels := [⟨"I_A1:tunnel", "I_A1", "I_B1", "inner", "IPsec", "tunnel", .observed, ["obs-00143", "obs-00145", "obs-00146", "obs-00147", "obs-00137", "obs-00136"]⟩, ⟨"O_A1:tunnel", "O_A1", "O_B1", "outer", "IPsec", "tunnel", .observed, ["obs-00173", "obs-00175", "obs-00176", "obs-00177", "obs-00167", "obs-00166"]⟩, ⟨"I_A2:tunnel", "I_A2", "I_B2", "inner", "IPsec", "tunnel", .observed, ["obs-00215", "obs-00217", "obs-00218", "obs-00219", "obs-00209", "obs-00208"]⟩, ⟨"I_B1:tunnel", "I_B1", "I_A1", "inner", "IPsec", "tunnel", .observed, ["obs-00269", "obs-00271", "obs-00272", "obs-00273", "obs-00263", "obs-00262"]⟩, ⟨"O_B1:tunnel", "O_B1", "O_A1", "outer", "IPsec", "tunnel", .observed, ["obs-00299", "obs-00301", "obs-00302", "obs-00303", "obs-00293", "obs-00292"]⟩, ⟨"I_B2:tunnel", "I_B2", "I_A2", "inner", "IPsec", "tunnel", .observed, ["obs-00341", "obs-00343", "obs-00344", "obs-00345", "obs-00335", "obs-00334"]⟩, ⟨"I_A3:tunnel", "I_A3", "I_B3", "inner", "IPsec", "tunnel", .observed, ["obs-00383", "obs-00385", "obs-00386", "obs-00387", "obs-00377", "obs-00376"]⟩, ⟨"I_B3:tunnel", "I_B3", "I_A3", "inner", "IPsec", "tunnel", .observed, ["obs-00425", "obs-00427", "obs-00428", "obs-00429", "obs-00419", "obs-00418"]⟩, ⟨"O_A2:tunnel", "O_A2", "O_B2", "outer", "IPsec", "tunnel", .observed, ["obs-00455", "obs-00457", "obs-00458", "obs-00459", "obs-00449", "obs-00448"]⟩, ⟨"O_B2:tunnel", "O_B2", "O_A2", "outer", "IPsec", "tunnel", .observed, ["obs-00485", "obs-00487", "obs-00488", "obs-00489", "obs-00479", "obs-00478"]⟩]

  probes := [⟨"probe-obs-00527", "R_A1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00527"]⟩, ⟨"probe-obs-00528", "R_A1", "10.2.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00528"]⟩, ⟨"probe-obs-00529", "R_A1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00529"]⟩, ⟨"probe-obs-00530", "R_A1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00530"]⟩, ⟨"probe-obs-00531", "R_A1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00531"]⟩, ⟨"probe-obs-00532", "R_A2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00532"]⟩, ⟨"probe-obs-00533", "R_A2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00533"]⟩, ⟨"probe-obs-00534", "R_A2", "10.2.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00534"]⟩, ⟨"probe-obs-00535", "R_A2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00535"]⟩, ⟨"probe-obs-00536", "R_A2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00536"]⟩, ⟨"probe-obs-00537", "R_B1", "10.1.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00537"]⟩, ⟨"probe-obs-00538", "R_B1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00538"]⟩, ⟨"probe-obs-00539", "R_B1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00539"]⟩, ⟨"probe-obs-00540", "R_B1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00540"]⟩, ⟨"probe-obs-00541", "R_B1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00541"]⟩, ⟨"probe-obs-00542", "R_B2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00542"]⟩, ⟨"probe-obs-00543", "R_B2", "10.1.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00543"]⟩, ⟨"probe-obs-00544", "R_B2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00544"]⟩, ⟨"probe-obs-00545", "R_B2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00545"]⟩, ⟨"probe-obs-00546", "R_B2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00546"]⟩, ⟨"probe-obs-00547", "R_A3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00547"]⟩, ⟨"probe-obs-00548", "R_A3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00548"]⟩, ⟨"probe-obs-00549", "R_A3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00549"]⟩, ⟨"probe-obs-00550", "R_A3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00550"]⟩, ⟨"probe-obs-00551", "R_A3", "10.2.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00551"]⟩, ⟨"probe-obs-00552", "R_B3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00552"]⟩, ⟨"probe-obs-00553", "R_B3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00553"]⟩, ⟨"probe-obs-00554", "R_B3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00554"]⟩, ⟨"probe-obs-00555", "R_B3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00555"]⟩, ⟨"probe-obs-00556", "R_B3", "10.1.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00556"]⟩]

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

def chain_GF_A_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "s1", .egress "g1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "s1", .egress "g1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "g1", .egress "s1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "g1", .egress "s1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "s2", .egress "g2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "s2", .egress "g2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "g2", .egress "s2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "g2", .egress "s2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "s3", .egress "g3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "s3", .egress "g3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "g3", .egress "s3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "g3", .egress "s3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

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

def chain_GF_B_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_GF_B_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "s1", .egress "g1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "s1", .egress "g1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "g1", .egress "s1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "g1", .egress "s1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "s2", .egress "g2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "s2", .egress "g2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "g2", .egress "s2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "g2", .egress "s2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "s3", .egress "g3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "s3", .egress "g3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "g3", .egress "s3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "g3", .egress "s3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

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

def chain_R_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_R_A3_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_R_A3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_R_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_R_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_R_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_I_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_I_A3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 103], .allow⟩]

theorem chain_I_A3_filters4_FORWARD_guarded : ∀ r ∈ chain_I_A3_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_A3_filters4_FORWARD; decide

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

theorem chain_I_B3_filters4_FORWARD_guarded : ∀ r ∈ chain_I_B3_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_I_B3_filters4_FORWARD; decide

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

def chain_O_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

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

def chain_O_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

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

def observedESPHardLifetimes : List Evidence.HardLifetimeFact := [⟨"I_A1", 0, 3600⟩, ⟨"I_A1", 1, 3600⟩, ⟨"O_A1", 0, 3600⟩, ⟨"O_A1", 1, 3600⟩, ⟨"I_A2", 0, 3600⟩, ⟨"I_A2", 1, 3600⟩, ⟨"I_B1", 0, 3600⟩, ⟨"I_B1", 1, 3600⟩, ⟨"O_B1", 0, 3600⟩, ⟨"O_B1", 1, 3600⟩, ⟨"I_B2", 0, 3600⟩, ⟨"I_B2", 1, 3600⟩, ⟨"I_A3", 0, 3600⟩, ⟨"I_A3", 1, 3600⟩, ⟨"I_B3", 0, 3600⟩, ⟨"I_B3", 1, 3600⟩, ⟨"O_A2", 0, 3600⟩, ⟨"O_A2", 1, 3600⟩, ⟨"O_B2", 0, 3600⟩, ⟨"O_B2", 1, 3600⟩]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩, ⟨6, 2, .gcm, .gcm, false⟩, ⟨7, 2, .gcm, .gcm, false⟩, ⟨8, 2, .gcm, .gcm, false⟩, ⟨9, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

def loadedVPNModePolicies : List Targets.VPNModePolicy := [⟨"I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_A3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"I_B3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"O_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide

end TDN.Imported.redundant_router_coherent_20261017T2149Z
