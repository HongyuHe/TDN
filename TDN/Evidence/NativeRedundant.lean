import TDN.Evidence.Types

import TDN.Semantics.PacketPolicy

namespace TDN.Imported.native_redundant_four_levels_20261017T2240Z_scope_v2

set_option maxRecDepth 100000

set_option maxHeartbeats 0

def snapshot : Evidence.Snapshot where

  id := "native-redundant-four-levels-20261017T2240Z-scope-v2"

  manifestSha256 := "84d4382b7252578a2549297f597e9d84530828f3526bd6838583fc7d783b22a9"

  snapshotSha256 := "6ae10cb197dfb0db40df45bd76f7dd7f05be2435dece2f388ae040a0e1765340"

  devices := [⟨"NR_BLACK", "transport", none, none, .observed, ["obs-00002", "obs-00123"]⟩, ⟨"NR_GF_A", "gray-firewall", some "A", none, .observed, ["obs-00004", "obs-00142"]⟩, ⟨"NR_R_A1", "host", some "A", some "TOP_SECRET", .observed, ["obs-00006", "obs-00159"]⟩, ⟨"NR_I_A1", "inner", some "A", some "TOP_SECRET", .observed, ["obs-00008", "obs-00171"]⟩, ⟨"NR_G_A1", "switch", some "A", some "TOP_SECRET", .observed, ["obs-00010", "obs-00189"]⟩, ⟨"NR_O_A1", "outer", some "A", some "shared", .observed, ["obs-00012", "obs-00208"]⟩, ⟨"NR_OF_A1", "firewall", some "A", some "S1", .observed, ["obs-00014", "obs-00226"]⟩, ⟨"NR_R_A2", "host", some "A", some "SECRET_US_ONLY", .observed, ["obs-00016", "obs-00245"]⟩, ⟨"NR_I_A2", "inner", some "A", some "SECRET_US_ONLY", .observed, ["obs-00018", "obs-00257"]⟩, ⟨"NR_G_A2", "switch", some "A", some "SECRET_US_ONLY", .observed, ["obs-00020", "obs-00275"]⟩, ⟨"NR_GF_B", "gray-firewall", some "B", none, .observed, ["obs-00022", "obs-00294"]⟩, ⟨"NR_R_B1", "host", some "B", some "TOP_SECRET", .observed, ["obs-00024", "obs-00311"]⟩, ⟨"NR_I_B1", "inner", some "B", some "TOP_SECRET", .observed, ["obs-00026", "obs-00323"]⟩, ⟨"NR_G_B1", "switch", some "B", some "TOP_SECRET", .observed, ["obs-00028", "obs-00341"]⟩, ⟨"NR_O_B1", "outer", some "B", some "shared", .observed, ["obs-00030", "obs-00360"]⟩, ⟨"NR_OF_B1", "firewall", some "B", some "S1", .observed, ["obs-00032", "obs-00378"]⟩, ⟨"NR_R_B2", "host", some "B", some "SECRET_US_ONLY", .observed, ["obs-00034", "obs-00397"]⟩, ⟨"NR_I_B2", "inner", some "B", some "SECRET_US_ONLY", .observed, ["obs-00036", "obs-00409"]⟩, ⟨"NR_G_B2", "switch", some "B", some "SECRET_US_ONLY", .observed, ["obs-00038", "obs-00427"]⟩, ⟨"NR_R_A3", "host", some "A", some "SECRET_COALITION", .observed, ["obs-00040", "obs-00446"]⟩, ⟨"NR_I_A3", "inner", some "A", some "SECRET_COALITION", .observed, ["obs-00042", "obs-00458"]⟩, ⟨"NR_G_A3", "switch", some "A", some "SECRET_COALITION", .observed, ["obs-00044", "obs-00476"]⟩, ⟨"NR_R_B3", "host", some "B", some "SECRET_COALITION", .observed, ["obs-00046", "obs-00495"]⟩, ⟨"NR_I_B3", "inner", some "B", some "SECRET_COALITION", .observed, ["obs-00048", "obs-00507"]⟩, ⟨"NR_G_B3", "switch", some "B", some "SECRET_COALITION", .observed, ["obs-00050", "obs-00525"]⟩, ⟨"NR_O_A2", "outer", some "A", some "shared", .observed, ["obs-00052", "obs-00544"]⟩, ⟨"NR_OF_A2", "firewall", some "A", some "S2", .observed, ["obs-00054", "obs-00562"]⟩, ⟨"NR_O_B2", "outer", some "B", some "shared", .observed, ["obs-00056", "obs-00581"]⟩, ⟨"NR_OF_B2", "firewall", some "B", some "S2", .observed, ["obs-00058", "obs-00599"]⟩, ⟨"NR_GR_A", "transport", some "A", none, .observed, ["obs-00060", "obs-00618"]⟩, ⟨"NR_GR_B", "transport", some "B", none, .observed, ["obs-00062", "obs-00635"]⟩, ⟨"NR_R_A4", "host", some "A", some "UNCLASSIFIED", .observed, ["obs-00064", "obs-00652"]⟩, ⟨"NR_I_A4", "inner", some "A", some "UNCLASSIFIED", .observed, ["obs-00066", "obs-00664"]⟩, ⟨"NR_G_A4", "switch", some "A", some "UNCLASSIFIED", .observed, ["obs-00068", "obs-00682"]⟩, ⟨"NR_R_B4", "host", some "B", some "UNCLASSIFIED", .observed, ["obs-00070", "obs-00701"]⟩, ⟨"NR_I_B4", "inner", some "B", some "UNCLASSIFIED", .observed, ["obs-00072", "obs-00713"]⟩, ⟨"NR_G_B4", "switch", some "B", some "UNCLASSIFIED", .observed, ["obs-00074", "obs-00731"]⟩]

  tunnels := [⟨"NR_I_A1:tunnel", "NR_I_A1", "NR_I_B1", "inner", "IPsec", "tunnel", .observed, ["obs-00173", "obs-00175", "obs-00176", "obs-00177", "obs-00167", "obs-00166"]⟩, ⟨"NR_O_A1:tunnel", "NR_O_A1", "NR_O_B1", "outer", "IPsec", "tunnel", .observed, ["obs-00210", "obs-00212", "obs-00213", "obs-00214", "obs-00204", "obs-00203"]⟩, ⟨"NR_I_A2:tunnel", "NR_I_A2", "NR_I_B2", "inner", "IPsec", "tunnel", .observed, ["obs-00259", "obs-00261", "obs-00262", "obs-00263", "obs-00253", "obs-00252"]⟩, ⟨"NR_I_B1:tunnel", "NR_I_B1", "NR_I_A1", "inner", "IPsec", "tunnel", .observed, ["obs-00325", "obs-00327", "obs-00328", "obs-00329", "obs-00319", "obs-00318"]⟩, ⟨"NR_O_B1:tunnel", "NR_O_B1", "NR_O_A1", "outer", "IPsec", "tunnel", .observed, ["obs-00362", "obs-00364", "obs-00365", "obs-00366", "obs-00356", "obs-00355"]⟩, ⟨"NR_I_B2:tunnel", "NR_I_B2", "NR_I_A2", "inner", "IPsec", "tunnel", .observed, ["obs-00411", "obs-00413", "obs-00414", "obs-00415", "obs-00405", "obs-00404"]⟩, ⟨"NR_I_A3:tunnel", "NR_I_A3", "NR_I_B3", "inner", "IPsec", "tunnel", .observed, ["obs-00460", "obs-00462", "obs-00463", "obs-00464", "obs-00454", "obs-00453"]⟩, ⟨"NR_I_B3:tunnel", "NR_I_B3", "NR_I_A3", "inner", "IPsec", "tunnel", .observed, ["obs-00509", "obs-00511", "obs-00512", "obs-00513", "obs-00503", "obs-00502"]⟩, ⟨"NR_O_A2:tunnel", "NR_O_A2", "NR_O_B2", "outer", "IPsec", "tunnel", .observed, ["obs-00546", "obs-00548", "obs-00549", "obs-00550", "obs-00540", "obs-00539"]⟩, ⟨"NR_O_B2:tunnel", "NR_O_B2", "NR_O_A2", "outer", "IPsec", "tunnel", .observed, ["obs-00583", "obs-00585", "obs-00586", "obs-00587", "obs-00577", "obs-00576"]⟩, ⟨"NR_I_A4:tunnel", "NR_I_A4", "NR_I_B4", "inner", "IPsec", "tunnel", .observed, ["obs-00666", "obs-00668", "obs-00669", "obs-00670", "obs-00660", "obs-00659"]⟩, ⟨"NR_I_B4:tunnel", "NR_I_B4", "NR_I_A4", "inner", "IPsec", "tunnel", .observed, ["obs-00715", "obs-00717", "obs-00718", "obs-00719", "obs-00709", "obs-00708"]⟩]

  probes := [⟨"probe-obs-00740", "NR_R_A1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00740"]⟩, ⟨"probe-obs-00741", "NR_R_A1", "10.2.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00741"]⟩, ⟨"probe-obs-00742", "NR_R_A1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00742"]⟩, ⟨"probe-obs-00743", "NR_R_A1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00743"]⟩, ⟨"probe-obs-00744", "NR_R_A1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00744"]⟩, ⟨"probe-obs-00745", "NR_R_A1", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00745"]⟩, ⟨"probe-obs-00746", "NR_R_A1", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00746"]⟩, ⟨"probe-obs-00747", "NR_R_A2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00747"]⟩, ⟨"probe-obs-00748", "NR_R_A2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00748"]⟩, ⟨"probe-obs-00749", "NR_R_A2", "10.2.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00749"]⟩, ⟨"probe-obs-00750", "NR_R_A2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00750"]⟩, ⟨"probe-obs-00751", "NR_R_A2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00751"]⟩, ⟨"probe-obs-00752", "NR_R_A2", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00752"]⟩, ⟨"probe-obs-00753", "NR_R_A2", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00753"]⟩, ⟨"probe-obs-00754", "NR_R_B1", "10.1.1.10", "same-level useful traffic", "delivered", .observed, ["obs-00754"]⟩, ⟨"probe-obs-00755", "NR_R_B1", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00755"]⟩, ⟨"probe-obs-00756", "NR_R_B1", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00756"]⟩, ⟨"probe-obs-00757", "NR_R_B1", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00757"]⟩, ⟨"probe-obs-00758", "NR_R_B1", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00758"]⟩, ⟨"probe-obs-00759", "NR_R_B1", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00759"]⟩, ⟨"probe-obs-00760", "NR_R_B1", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00760"]⟩, ⟨"probe-obs-00761", "NR_R_B2", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00761"]⟩, ⟨"probe-obs-00762", "NR_R_B2", "10.1.2.10", "same-level useful traffic", "delivered", .observed, ["obs-00762"]⟩, ⟨"probe-obs-00763", "NR_R_B2", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00763"]⟩, ⟨"probe-obs-00764", "NR_R_B2", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00764"]⟩, ⟨"probe-obs-00765", "NR_R_B2", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00765"]⟩, ⟨"probe-obs-00766", "NR_R_B2", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00766"]⟩, ⟨"probe-obs-00767", "NR_R_B2", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00767"]⟩, ⟨"probe-obs-00768", "NR_R_A3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00768"]⟩, ⟨"probe-obs-00769", "NR_R_A3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00769"]⟩, ⟨"probe-obs-00770", "NR_R_A3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00770"]⟩, ⟨"probe-obs-00771", "NR_R_A3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00771"]⟩, ⟨"probe-obs-00772", "NR_R_A3", "10.2.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00772"]⟩, ⟨"probe-obs-00773", "NR_R_A3", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00773"]⟩, ⟨"probe-obs-00774", "NR_R_A3", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00774"]⟩, ⟨"probe-obs-00775", "NR_R_B3", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00775"]⟩, ⟨"probe-obs-00776", "NR_R_B3", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00776"]⟩, ⟨"probe-obs-00777", "NR_R_B3", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00777"]⟩, ⟨"probe-obs-00778", "NR_R_B3", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00778"]⟩, ⟨"probe-obs-00779", "NR_R_B3", "10.1.3.10", "same-level useful traffic", "delivered", .observed, ["obs-00779"]⟩, ⟨"probe-obs-00780", "NR_R_B3", "10.1.4.10", "cross-level denial", "no_reply", .observed, ["obs-00780"]⟩, ⟨"probe-obs-00781", "NR_R_B3", "10.2.4.10", "cross-level denial", "no_reply", .observed, ["obs-00781"]⟩, ⟨"probe-obs-00782", "NR_R_A4", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00782"]⟩, ⟨"probe-obs-00783", "NR_R_A4", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00783"]⟩, ⟨"probe-obs-00784", "NR_R_A4", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00784"]⟩, ⟨"probe-obs-00785", "NR_R_A4", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00785"]⟩, ⟨"probe-obs-00786", "NR_R_A4", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00786"]⟩, ⟨"probe-obs-00787", "NR_R_A4", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00787"]⟩, ⟨"probe-obs-00788", "NR_R_A4", "10.2.4.10", "same-level useful traffic", "delivered", .observed, ["obs-00788"]⟩, ⟨"probe-obs-00789", "NR_R_B4", "10.1.1.10", "cross-level denial", "no_reply", .observed, ["obs-00789"]⟩, ⟨"probe-obs-00790", "NR_R_B4", "10.1.2.10", "cross-level denial", "no_reply", .observed, ["obs-00790"]⟩, ⟨"probe-obs-00791", "NR_R_B4", "10.2.1.10", "cross-level denial", "no_reply", .observed, ["obs-00791"]⟩, ⟨"probe-obs-00792", "NR_R_B4", "10.2.2.10", "cross-level denial", "no_reply", .observed, ["obs-00792"]⟩, ⟨"probe-obs-00793", "NR_R_B4", "10.1.3.10", "cross-level denial", "no_reply", .observed, ["obs-00793"]⟩, ⟨"probe-obs-00794", "NR_R_B4", "10.2.3.10", "cross-level denial", "no_reply", .observed, ["obs-00794"]⟩, ⟨"probe-obs-00795", "NR_R_B4", "10.1.4.10", "same-level useful traffic", "delivered", .observed, ["obs-00795"]⟩]

lemma observed_provenance : Evidence.HasProvenance snapshot := by unfold Evidence.HasProvenance snapshot; decide

theorem useful_observed_traffic : Evidence.HasObservedSuccess snapshot := by unfold Evidence.HasObservedSuccess snapshot; decide

theorem observed_ipsec_tunnel_modes : Evidence.IPsecTunnelModes snapshot := by unfold Evidence.IPsecTunnelModes snapshot; decide

theorem observed_inner_peers_same_declared_level : Evidence.InnerPeersSameDeclaredLevel snapshot := by unfold Evidence.InnerPeersSameDeclaredLevel snapshot; decide

def chain_NR_BLACK_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .ingress "p11", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .ingress "p21", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060481 2887060481, .ingress "p12", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887063041 2887063041, .ingress "p22", .protocol "ospf"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_BLACK_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_BLACK_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_BLACK_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_BLACK_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_BLACK_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_GF_A_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_NR_GF_A_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "s1", .egress "g1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "s1", .egress "g1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "g1", .egress "s1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "g1", .egress "s1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "s2", .egress "g2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "s2", .egress "g2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "g2", .egress "s2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "g2", .egress "s2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "s3", .egress "g3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "s3", .egress "g3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "g3", .egress "s3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "g3", .egress "s3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "s4", .egress "g4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "s4", .egress "g4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "g4", .egress "s4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "g4", .egress "s4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NR_GF_A_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_NR_GF_A_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_GF_A_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_GF_A_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NR_R_A1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_R_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_I_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_NR_I_A1_filters4_FORWARD_guarded : ∀ r ∈ chain_NR_I_A1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NR_I_A1_filters4_FORWARD; decide

theorem chain_NR_I_A1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NR_I_A1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NR_I_A1_filters4_FORWARD "red" "gray" chain_NR_I_A1_filters4_FORWARD_guarded p accepted

def chain_NR_I_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_I_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_I_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_G_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_G_A1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_G_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_G_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_O_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NR_O_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

def chain_NR_O_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NR_O_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_O_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_O_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_OF_A1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 2887060225 2887060225, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060226 2887060226, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NR_OF_A1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NR_OF_A1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 2887060226 2887060226, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060225 2887060225, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NR_OF_A1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_OF_A1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_OF_A1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NR_R_A2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_R_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_I_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_NR_I_A2_filters4_FORWARD_guarded : ∀ r ∈ chain_NR_I_A2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NR_I_A2_filters4_FORWARD; decide

theorem chain_NR_I_A2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NR_I_A2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NR_I_A2_filters4_FORWARD "red" "gray" chain_NR_I_A2_filters4_FORWARD_guarded p accepted

def chain_NR_I_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_I_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_I_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_G_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_G_A2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_G_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_G_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_GF_B_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩]

def chain_NR_GF_B_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "s1", .egress "g1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "s1", .egress "g1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "g1", .egress "s1", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "g1", .egress "s1", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "s2", .egress "g2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "s2", .egress "g2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "g2", .egress "s2", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "g2", .egress "s2", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "s3", .egress "g3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "s3", .egress "g3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "g3", .egress "s3", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "g3", .egress "s3", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "s4", .egress "g4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "s4", .egress "g4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "g4", .egress "s4", .protocol "esp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "g4", .egress "s4", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NR_GF_B_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩]

def chain_NR_GF_B_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_GF_B_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_GF_B_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NR_R_B1_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_R_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_I_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 101], .allow⟩, ⟨[.sourceRange 167903488 167903743, .destinationRange 167837952 167838207, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 101], .allow⟩, ⟨[.sourceRange 167837952 167838207, .destinationRange 167903488 167903743, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 101], .allow⟩]

lemma chain_NR_I_B1_filters4_FORWARD_guarded : ∀ r ∈ chain_NR_I_B1_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NR_I_B1_filters4_FORWARD; decide

theorem chain_NR_I_B1_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NR_I_B1_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NR_I_B1_filters4_FORWARD "red" "gray" chain_NR_I_B1_filters4_FORWARD_guarded p accepted

def chain_NR_I_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_I_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_I_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_G_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_G_B1_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_G_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_G_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_O_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NR_O_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩]

def chain_NR_O_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NR_O_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_O_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_O_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_OF_B1_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 2887062785 2887062785, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062786 2887062786, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NR_OF_B1_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997249 2886997249, .destinationRange 2886994689 2886994689, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994689 2886994689, .destinationRange 2886997249 2886997249, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NR_OF_B1_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 2887062786 2887062786, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887062785 2887062785, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NR_OF_B1_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_OF_B1_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_OF_B1_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NR_R_B2_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_R_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_I_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 102], .allow⟩, ⟨[.sourceRange 167903744 167903999, .destinationRange 167838208 167838463, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 102], .allow⟩, ⟨[.sourceRange 167838208 167838463, .destinationRange 167903744 167903999, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 102], .allow⟩]

lemma chain_NR_I_B2_filters4_FORWARD_guarded : ∀ r ∈ chain_NR_I_B2_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NR_I_B2_filters4_FORWARD; decide

theorem chain_NR_I_B2_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NR_I_B2_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NR_I_B2_filters4_FORWARD "red" "gray" chain_NR_I_B2_filters4_FORWARD_guarded p accepted

def chain_NR_I_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_I_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_I_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_G_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_G_B2_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_G_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_G_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NR_R_A3_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_A3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_R_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_I_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_A3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 103], .allow⟩]

lemma chain_NR_I_A3_filters4_FORWARD_guarded : ∀ r ∈ chain_NR_I_A3_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NR_I_A3_filters4_FORWARD; decide

theorem chain_NR_I_A3_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NR_I_A3_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NR_I_A3_filters4_FORWARD "red" "gray" chain_NR_I_A3_filters4_FORWARD_guarded p accepted

def chain_NR_I_A3_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_I_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_I_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_A3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_G_A3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_G_A3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_A3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_G_A3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_G_A3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_B3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NR_R_B3_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_B3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_B3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_R_B3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_B3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_I_B3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_B3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 103], .allow⟩, ⟨[.sourceRange 167904000 167904255, .destinationRange 167838464 167838719, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 103], .allow⟩, ⟨[.sourceRange 167838464 167838719, .destinationRange 167904000 167904255, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 103], .allow⟩]

lemma chain_NR_I_B3_filters4_FORWARD_guarded : ∀ r ∈ chain_NR_I_B3_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NR_I_B3_filters4_FORWARD; decide

theorem chain_NR_I_B3_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NR_I_B3_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NR_I_B3_filters4_FORWARD "red" "gray" chain_NR_I_B3_filters4_FORWARD_guarded p accepted

def chain_NR_I_B3_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_B3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_I_B3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_I_B3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_B3_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_G_B3_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_G_B3_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_B3_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_G_B3_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_G_B3_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_O_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NR_O_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

def chain_NR_O_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NR_O_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_O_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_O_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_OF_A2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887060482 2887060482, .destinationRange 2887060481 2887060481, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060482 2887060482, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NR_OF_A2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NR_OF_A2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887060481 2887060481, .destinationRange 2887060482 2887060482, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887060481 2887060481, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NR_OF_A2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_OF_A2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_OF_A2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_O_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.ingress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NR_O_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray2", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray2", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880130 180880130, .destinationRange 174326530 174326530, .ingress "gray3", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326530 174326530, .destinationRange 180880130 180880130, .ingress "black", .egress "gray3", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray4", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "black", .egress "gray4", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]

def chain_NR_O_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "udp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "esp", .ipv4HeaderWords 5], .allow⟩, ⟨[.egress "lo", .protocol "icmp", .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .egress "black", .protocol "esp", .ipv4HeaderWords 5], .allow⟩]

def chain_NR_O_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_O_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_O_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_OF_B2_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.sourceRange 2887063042 2887063042, .destinationRange 2887063041 2887063041, .ingress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887063042 2887063042, .destinationRange 3758096389 3758096389, .ingress "outside", .protocol "ospf"], .allow⟩]

def chain_NR_OF_B2_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "inside", .egress "outside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886997505 2886997505, .destinationRange 2886994945 2886994945, .ingress "inside", .egress "outside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "outside", .egress "inside", .protocol "esp"], .allow⟩, ⟨[.sourceRange 2886994945 2886994945, .destinationRange 2886997505 2886997505, .ingress "outside", .egress "inside", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩]

def chain_NR_OF_B2_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo"], .allow⟩, ⟨[.sourceRange 2887063041 2887063041, .destinationRange 2887063042 2887063042, .egress "outside", .protocol "ospf"], .allow⟩, ⟨[.sourceRange 2887063041 2887063041, .destinationRange 3758096389 3758096389, .egress "outside", .protocol "ospf"], .allow⟩]

def chain_NR_OF_B2_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_OF_B2_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_OF_B2_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_GR_A_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_GR_A_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_GR_A_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_GR_A_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_GR_A_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_GR_A_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_GR_B_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_GR_B_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_GR_B_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_GR_B_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_GR_B_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_GR_B_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_A4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NR_R_A4_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_A4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_A4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_R_A4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_A4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_I_A4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_A4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 104], .allow⟩]

lemma chain_NR_I_A4_filters4_FORWARD_guarded : ∀ r ∈ chain_NR_I_A4_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NR_I_A4_filters4_FORWARD; decide

theorem chain_NR_I_A4_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NR_I_A4_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NR_I_A4_filters4_FORWARD "red" "gray" chain_NR_I_A4_filters4_FORWARD_guarded p accepted

def chain_NR_I_A4_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_A4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_I_A4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_I_A4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_A4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_G_A4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_G_A4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_A4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_G_A4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_G_A4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_B4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩, ⟨[.connectionStates ["RELATED", "ESTABLISHED"]], .allow⟩]

def chain_NR_R_B4_filters4_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_B4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_R_B4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_R_B4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_R_B4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_I_B4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo", .protocol "tcp"], .allow⟩, ⟨[.ingress "lo", .protocol "udp"], .allow⟩, ⟨[.ingress "lo", .protocol "esp"], .allow⟩, ⟨[.ingress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 174326786 174326786, .destinationRange 180880386 180880386, .ingress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_B4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "tcp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "tcp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "udp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "udp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "esp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "esp", .inboundPolicy 104], .allow⟩, ⟨[.sourceRange 167904256 167904511, .destinationRange 167838720 167838975, .ingress "red", .egress "gray", .protocol "icmp", .outboundPolicy 104], .allow⟩, ⟨[.sourceRange 167838720 167838975, .destinationRange 167904256 167904511, .ingress "gray", .egress "red", .protocol "icmp", .inboundPolicy 104], .allow⟩]

lemma chain_NR_I_B4_filters4_FORWARD_guarded : ∀ r ∈ chain_NR_I_B4_filters4_FORWARD, r.verdict = .allow → PacketPolicy.Guarded r "red" "gray" := by unfold chain_NR_I_B4_filters4_FORWARD; decide

theorem chain_NR_I_B4_filters4_FORWARD_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate (chain_NR_I_B4_filters4_FORWARD.map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "red" "gray" p := PacketPolicy.forwarding_policy_protects chain_NR_I_B4_filters4_FORWARD "red" "gray" chain_NR_I_B4_filters4_FORWARD_guarded p accepted

def chain_NR_I_B4_filters4_OUTPUT : List PacketPolicy.Rule := [⟨[.egress "lo", .protocol "tcp"], .allow⟩, ⟨[.egress "lo", .protocol "udp"], .allow⟩, ⟨[.egress "lo", .protocol "esp"], .allow⟩, ⟨[.egress "lo", .protocol "icmp"], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .egress "gray", .protocol "udp", .destinationPorts [500, 4500]], .allow⟩, ⟨[.sourceRange 180880386 180880386, .destinationRange 174326786 174326786, .egress "gray", .protocol "esp"], .allow⟩]

def chain_NR_I_B4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_I_B4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_I_B4_filters6_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_B4_filters4_INPUT : List PacketPolicy.Rule := [⟨[.ingress "lo"], .allow⟩, ⟨[.protocol "icmp"], .allow⟩]

def chain_NR_G_B4_filters4_FORWARD : List PacketPolicy.Rule := [⟨[], .allow⟩]

def chain_NR_G_B4_filters4_OUTPUT : List PacketPolicy.Rule := []

def chain_NR_G_B4_filters6_INPUT : List PacketPolicy.Rule := []

def chain_NR_G_B4_filters6_FORWARD : List PacketPolicy.Rule := []

def chain_NR_G_B4_filters6_OUTPUT : List PacketPolicy.Rule := []

def observedESPHardLifetimes : List Evidence.HardLifetimeFact := [⟨"NR_I_A1", 0, 3600⟩, ⟨"NR_I_A1", 1, 3600⟩, ⟨"NR_O_A1", 0, 3600⟩, ⟨"NR_O_A1", 1, 3600⟩, ⟨"NR_I_A2", 0, 3600⟩, ⟨"NR_I_A2", 1, 3600⟩, ⟨"NR_I_B1", 0, 3600⟩, ⟨"NR_I_B1", 1, 3600⟩, ⟨"NR_O_B1", 0, 3600⟩, ⟨"NR_O_B1", 1, 3600⟩, ⟨"NR_I_B2", 0, 3600⟩, ⟨"NR_I_B2", 1, 3600⟩, ⟨"NR_I_A3", 0, 3600⟩, ⟨"NR_I_A3", 1, 3600⟩, ⟨"NR_I_B3", 0, 3600⟩, ⟨"NR_I_B3", 1, 3600⟩, ⟨"NR_O_A2", 0, 3600⟩, ⟨"NR_O_A2", 1, 3600⟩, ⟨"NR_O_B2", 0, 3600⟩, ⟨"NR_O_B2", 1, 3600⟩, ⟨"NR_I_A4", 0, 3600⟩, ⟨"NR_I_A4", 1, 3600⟩, ⟨"NR_I_B4", 0, 3600⟩, ⟨"NR_I_B4", 1, 3600⟩]

theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide

def observedVPNModes : List Targets.VPNConfig := [⟨0, 2, .gcm, .gcm, false⟩, ⟨1, 2, .gcm, .gcm, false⟩, ⟨2, 2, .gcm, .gcm, false⟩, ⟨3, 2, .gcm, .gcm, false⟩, ⟨4, 2, .gcm, .gcm, false⟩, ⟨5, 2, .gcm, .gcm, false⟩, ⟨6, 2, .gcm, .gcm, false⟩, ⟨7, 2, .gcm, .gcm, false⟩, ⟨8, 2, .gcm, .gcm, false⟩, ⟨9, 2, .gcm, .gcm, false⟩, ⟨10, 2, .gcm, .gcm, false⟩, ⟨11, 2, .gcm, .gcm, false⟩]

theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide

def loadedVPNModePolicies : List Targets.VPNModePolicy := [⟨"NR_I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_I_A3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_I_B3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_O_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_O_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_I_A4/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NR_I_B4/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide

end TDN.Imported.native_redundant_four_levels_20261017T2240Z_scope_v2
