import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.native_management_20261017T2241Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def snapshot : Evidence.Snapshot where

  id := "native-management-20261017T2241Z"

  manifestSha256 := "b56d60f3d4906349399d12f46e711820797fc6a5a45dd98f479e2ca43dbdbcec"

  snapshotSha256 := "5bfaa9bf84e7847e0ad1fd736c7cf5efa486f0270461692a7460c4c280bed728"

  devices := [⟨"NM_BLACK", "transport", none, none, .observed, ["obs-00002", "obs-00117"]⟩, ⟨"NM_GF_A", "gray-firewall", some "A", none, .observed, ["obs-00004", "obs-00136"]⟩, ⟨"NM_R_A1", "host", some "A", some "S1", .observed, ["obs-00006", "obs-00153"]⟩, ⟨"NM_I_A1", "inner", some "A", some "S1", .observed, ["obs-00008", "obs-00165"]⟩, ⟨"NM_G_A1", "switch", some "A", some "S1", .observed, ["obs-00010", "obs-00183"]⟩, ⟨"NM_O_A1", "outer", some "A", some "S1", .observed, ["obs-00012", "obs-00202"]⟩, ⟨"NM_OF_A1", "firewall", some "A", some "S1", .observed, ["obs-00014", "obs-00220"]⟩, ⟨"NM_R_A2", "host", some "A", some "S2", .observed, ["obs-00016", "obs-00239"]⟩, ⟨"NM_I_A2", "inner", some "A", some "S2", .observed, ["obs-00018", "obs-00251"]⟩, ⟨"NM_G_A2", "switch", some "A", some "S2", .observed, ["obs-00020", "obs-00269"]⟩, ⟨"NM_O_A2", "outer", some "A", some "S2", .observed, ["obs-00022", "obs-00288"]⟩, ⟨"NM_OF_A2", "firewall", some "A", some "S2", .observed, ["obs-00024", "obs-00306"]⟩, ⟨"NM_M_A1", "switch", some "A", some "management", .observed, ["obs-00026", "obs-00325"]⟩, ⟨"NM_AW_A1", "admin", some "A", some "management", .observed, ["obs-00028", "obs-00344"]⟩, ⟨"NM_M_A2", "switch", some "A", some "management", .observed, ["obs-00030", "obs-00356"]⟩, ⟨"NM_AW_A2", "admin", some "A", some "management", .observed, ["obs-00032", "obs-00375"]⟩, ⟨"NM_M_A99", "switch", some "A", some "management", .observed, ["obs-00034", "obs-00387"]⟩, ⟨"NM_AW_A99", "admin", some "A", some "management", .observed, ["obs-00036", "obs-00406"]⟩, ⟨"NM_GF_B", "gray-firewall", some "B", none, .observed, ["obs-00038", "obs-00418"]⟩, ⟨"NM_R_B1", "host", some "B", some "S1", .observed, ["obs-00040", "obs-00435"]⟩, ⟨"NM_I_B1", "inner", some "B", some "S1", .observed, ["obs-00042", "obs-00447"]⟩, ⟨"NM_G_B1", "switch", some "B", some "S1", .observed, ["obs-00044", "obs-00465"]⟩, ⟨"NM_O_B1", "outer", some "B", some "S1", .observed, ["obs-00046", "obs-00484"]⟩, ⟨"NM_OF_B1", "firewall", some "B", some "S1", .observed, ["obs-00048", "obs-00502"]⟩, ⟨"NM_R_B2", "host", some "B", some "S2", .observed, ["obs-00050", "obs-00521"]⟩, ⟨"NM_I_B2", "inner", some "B", some "S2", .observed, ["obs-00052", "obs-00533"]⟩, ⟨"NM_G_B2", "switch", some "B", some "S2", .observed, ["obs-00054", "obs-00551"]⟩, ⟨"NM_O_B2", "outer", some "B", some "S2", .observed, ["obs-00056", "obs-00570"]⟩, ⟨"NM_OF_B2", "firewall", some "B", some "S2", .observed, ["obs-00058", "obs-00588"]⟩, ⟨"NM_M_B1", "switch", some "B", some "management", .observed, ["obs-00060", "obs-00607"]⟩, ⟨"NM_AW_B1", "admin", some "B", some "management", .observed, ["obs-00062", "obs-00626"]⟩, ⟨"NM_M_B2", "switch", some "B", some "management", .observed, ["obs-00064", "obs-00638"]⟩, ⟨"NM_AW_B2", "admin", some "B", some "management", .observed, ["obs-00066", "obs-00657"]⟩, ⟨"NM_M_B99", "switch", some "B", some "management", .observed, ["obs-00068", "obs-00669"]⟩, ⟨"NM_AW_B99", "admin", some "B", some "management", .observed, ["obs-00070", "obs-00688"]⟩]

  tunnels := [⟨"NM_I_A1:tunnel", "NM_I_A1", "NM_I_B1", "inner", "IPsec", "tunnel", .observed, ["obs-00167", "obs-00169", "obs-00170", "obs-00171", "obs-00161", "obs-00160"]⟩, ⟨"NM_O_A1:tunnel", "NM_O_A1", "NM_O_B1", "outer", "IPsec", "tunnel", .observed, ["obs-00204", "obs-00206", "obs-00207", "obs-00208", "obs-00198", "obs-00197"]⟩, ⟨"NM_I_A2:tunnel", "NM_I_A2", "NM_I_B2", "inner", "IPsec", "tunnel", .observed, ["obs-00253", "obs-00255", "obs-00256", "obs-00257", "obs-00247", "obs-00246"]⟩, ⟨"NM_O_A2:tunnel", "NM_O_A2", "NM_O_B2", "outer", "IPsec", "tunnel", .observed, ["obs-00290", "obs-00292", "obs-00293", "obs-00294", "obs-00284", "obs-00283"]⟩, ⟨"NM_I_B1:tunnel", "NM_I_B1", "NM_I_A1", "inner", "IPsec", "tunnel", .observed, ["obs-00449", "obs-00451", "obs-00452", "obs-00453", "obs-00443", "obs-00442"]⟩, ⟨"NM_O_B1:tunnel", "NM_O_B1", "NM_O_A1", "outer", "IPsec", "tunnel", .observed, ["obs-00486", "obs-00488", "obs-00489", "obs-00490", "obs-00480", "obs-00479"]⟩, ⟨"NM_I_B2:tunnel", "NM_I_B2", "NM_I_A2", "inner", "IPsec", "tunnel", .observed, ["obs-00535", "obs-00537", "obs-00538", "obs-00539", "obs-00529", "obs-00528"]⟩, ⟨"NM_O_B2:tunnel", "NM_O_B2", "NM_O_A2", "outer", "IPsec", "tunnel", .observed, ["obs-00572", "obs-00574", "obs-00575", "obs-00576", "obs-00566", "obs-00565"]⟩]

  probes := [⟨"probe-obs-00690", "NM_R_A1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00690"]⟩, ⟨"probe-obs-00691", "NM_R_A1", "10.2.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00691"]⟩, ⟨"probe-obs-00692", "NM_R_A1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00692"]⟩, ⟨"probe-obs-00693", "NM_R_A2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00693"]⟩, ⟨"probe-obs-00694", "NM_R_A2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00694"]⟩, ⟨"probe-obs-00695", "NM_R_A2", "10.2.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00695"]⟩, ⟨"probe-obs-00696", "NM_R_B1", "10.1.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00696"]⟩, ⟨"probe-obs-00697", "NM_R_B1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00697"]⟩, ⟨"probe-obs-00698", "NM_R_B1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00698"]⟩, ⟨"probe-obs-00699", "NM_R_B2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00699"]⟩, ⟨"probe-obs-00700", "NM_R_B2", "10.1.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00700"]⟩, ⟨"probe-obs-00701", "NM_R_B2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00701"]⟩]

lemma observed_provenance : Evidence.HasProvenance snapshot := by unfold Evidence.HasProvenance snapshot; decide

theorem useful_observed_traffic : Evidence.HasObservedSuccess snapshot := by unfold Evidence.HasObservedSuccess snapshot; decide

theorem observed_ipsec_tunnel_modes : Evidence.IPsecTunnelModes snapshot := by unfold Evidence.IPsecTunnelModes snapshot; decide

theorem observed_inner_peers_same_declared_level : Evidence.InnerPeersSameDeclaredLevel snapshot := by unfold Evidence.InnerPeersSameDeclaredLevel snapshot; decide

def chain_NM_BLACK_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .ingress "p11", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060481 2887060481, .ingress "p12", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .ingress "p21", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887063041 2887063041, .ingress "p22", .protocol "ospf"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_BLACK_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_BLACK_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_BLACK_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_BLACK_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_BLACK_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_GF_A_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩]

def chain_NM_GF_A_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_GF_A_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩]

def chain_NM_GF_A_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_GF_A_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_GF_A_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_R_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_R_A1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_R_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_R_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_R_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_R_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_I_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887650058 2887650058, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887650058 2887650058, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NM_I_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_NM_I_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_NM_I_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NM_I_A1_filters4_FORWARD; decide

theorem chain_NM_I_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NM_I_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NM_I_A1_filters4_FORWARD "red" "gray" chain_NM_I_A1_filters4_FORWARD_guarded p accepted

def chain_NM_I_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887650058 2887650058, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887650058 2887650058, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NM_I_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_I_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_I_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_G_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_G_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_G_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_G_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_G_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_G_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_O_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NM_O_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

lemma chain_NM_O_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_NM_O_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_NM_O_A1_filters4_FORWARD; decide

theorem chain_NM_O_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NM_O_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_NM_O_A1_filters4_FORWARD "gray" "black" chain_NM_O_A1_filters4_FORWARD_guarded p accepted

def chain_NM_O_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "tcp", .sourcePorts [8443], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NM_O_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_O_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_O_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_OF_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 2887060225 2887060225, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NM_OF_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NM_OF_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 2887060226 2887060226, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NM_OF_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_OF_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_OF_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_R_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_R_A2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_R_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_R_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_R_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_R_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_I_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887650314 2887650314, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887650314 2887650314, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NM_I_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_NM_I_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_NM_I_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NM_I_A2_filters4_FORWARD; decide

theorem chain_NM_I_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NM_I_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NM_I_A2_filters4_FORWARD "red" "gray" chain_NM_I_A2_filters4_FORWARD_guarded p accepted

def chain_NM_I_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887650314 2887650314, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887650314 2887650314, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NM_I_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_I_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_I_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_G_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_G_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_G_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_G_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_G_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_G_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_O_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NM_O_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

lemma chain_NM_O_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_NM_O_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_NM_O_A2_filters4_FORWARD; decide

theorem chain_NM_O_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NM_O_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_NM_O_A2_filters4_FORWARD "gray" "black" chain_NM_O_A2_filters4_FORWARD_guarded p accepted

def chain_NM_O_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "tcp", .sourcePorts [8443], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NM_O_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_O_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_O_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_OF_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887675146 2887675146, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩, ⟨[.sourceRange 2887060482 2887060482, .destinationRange 2887060481 2887060481, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060482 2887060482, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NM_OF_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NM_OF_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887675146 2887675146, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩, ⟨[.sourceRange 2887060481 2887060481, .destinationRange 2887060482 2887060482, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060481 2887060481, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NM_OF_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_OF_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_OF_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_M_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_M_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_M_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_M_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_AW_A1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_AW_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_M_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_M_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_M_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_M_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_AW_A2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_AW_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_A99_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_M_A99_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_M_A99_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_A99_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_M_A99_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_M_A99_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_A99_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_AW_A99_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_A99_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_A99_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_AW_A99_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_A99_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_GF_B_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩]

def chain_NM_GF_B_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_GF_B_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩]

def chain_NM_GF_B_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_GF_B_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_GF_B_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_R_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_R_B1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_R_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_R_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_R_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_R_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_I_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887652618 2887652618, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887652618 2887652618, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NM_I_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_NM_I_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_NM_I_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NM_I_B1_filters4_FORWARD; decide

theorem chain_NM_I_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NM_I_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NM_I_B1_filters4_FORWARD "red" "gray" chain_NM_I_B1_filters4_FORWARD_guarded p accepted

def chain_NM_I_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887652618 2887652618, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887652618 2887652618, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NM_I_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_I_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_I_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_G_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_G_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_G_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_G_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_G_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_G_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_O_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NM_O_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

lemma chain_NM_O_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_NM_O_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_NM_O_B1_filters4_FORWARD; decide

theorem chain_NM_O_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NM_O_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_NM_O_B1_filters4_FORWARD "gray" "black" chain_NM_O_B1_filters4_FORWARD_guarded p accepted

def chain_NM_O_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "tcp", .sourcePorts [8443], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NM_O_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_O_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_O_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_OF_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 2887062785 2887062785, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NM_OF_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NM_OF_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 2887062786 2887062786, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NM_OF_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_OF_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_OF_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_R_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_R_B2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_R_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_R_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_R_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_R_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_I_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887652874 2887652874, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887652874 2887652874, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NM_I_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_NM_I_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_NM_I_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NM_I_B2_filters4_FORWARD; decide

theorem chain_NM_I_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NM_I_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NM_I_B2_filters4_FORWARD "red" "gray" chain_NM_I_B2_filters4_FORWARD_guarded p accepted

def chain_NM_I_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887652874 2887652874, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887652874 2887652874, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NM_I_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_I_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_I_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_G_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_G_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_G_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_G_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_G_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_G_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_O_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NM_O_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

lemma chain_NM_O_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_NM_O_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "gray" "black" := by unfold chain_NM_O_B2_filters4_FORWARD; decide

theorem chain_NM_O_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NM_O_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "gray" "black" p := PacketPolicy.forwarding_policy_protects chain_NM_O_B2_filters4_FORWARD "gray" "black" chain_NM_O_B2_filters4_FORWARD_guarded p accepted

def chain_NM_O_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "tcp", .sourcePorts [8443], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NM_O_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_O_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_O_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_OF_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 2887677706 2887677706, .ingress "mgmt", .protocol "tcp", .destinationPorts [8443]], .allow⟩, ⟨[.sourceRange 2887063042 2887063042, .destinationRange 2887063041 2887063041, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887063042 2887063042, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NM_OF_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NM_OF_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "icmp"], .allow⟩, ⟨[.destinationRange 2887677706 2887677706, .egress "mgmt", .protocol "tcp", .sourcePorts [8443]], .allow⟩, ⟨[.sourceRange 2887063041 2887063041, .destinationRange 2887063042 2887063042, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887063041 2887063041, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NM_OF_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_OF_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_OF_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_M_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_M_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_M_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_M_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_AW_B1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_AW_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_M_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_M_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_M_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_M_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_AW_B2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_AW_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_B99_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NM_M_B99_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NM_M_B99_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_M_B99_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_M_B99_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_M_B99_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_B99_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NM_AW_B99_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_B99_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NM_AW_B99_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NM_AW_B99_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NM_AW_B99_filters6_OUTPUT : List PacketPolicy.Rule := []

def observedESPHardLifetimes : List Evidence.HardLifetimeFact := [⟨"NM_I_A1", 0, 3600⟩, ⟨"NM_I_A1", 1, 3600⟩, ⟨"NM_O_A1", 0, 3600⟩, ⟨"NM_O_A1", 1, 3600⟩, ⟨"NM_I_A2", 0, 3600⟩, ⟨"NM_I_A2", 1, 3600⟩, ⟨"NM_O_A2", 0, 3600⟩, ⟨"NM_O_A2", 1, 3600⟩, ⟨"NM_I_B1", 0, 3600⟩, ⟨"NM_I_B1", 1, 3600⟩, ⟨"NM_O_B1", 0, 3600⟩, ⟨"NM_O_B1", 1, 3600⟩, ⟨"NM_I_B2", 0, 3600⟩, ⟨"NM_I_B2", 1, 3600⟩, ⟨"NM_O_B2", 0, 3600⟩, ⟨"NM_O_B2", 1, 3600⟩]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩, ⟨6, 2, .gcm, .gcm, false⟩, ⟨7, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

def loadedVPNModePolicies : List Targets.VPNModePolicy := [⟨"NM_I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NM_O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NM_I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NM_O_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NM_I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NM_O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NM_I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NM_O_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide

end TDN.Imported.native_management_20261017T2241Z
