import TDN.Targets.Addressing

namespace TDN.Imported.FreshBaselineAddressing

set_option maxRecDepth 100000
set_option maxHeartbeats 0

def ranges : List (Addressing.Range SecurityLevel) := [⟨174326018, 174326018, ⟨"SECRET", {}, {}, {}⟩⟩, ⟨174326274, 174326274, ⟨"TOP_SECRET", {}, {}, {}⟩⟩, ⟨180879618, 180879618, ⟨"SECRET", {}, {}, {}⟩⟩, ⟨180879874, 180879874, ⟨"TOP_SECRET", {}, {}, {}⟩⟩]

def pairs : List Targets.IntendedAddressPair := [⟨174326018, 180879618, ⟨"SECRET", {}, {}, {}⟩⟩, ⟨174326274, 180879874, ⟨"TOP_SECRET", {}, {}, {}⟩⟩, ⟨180879618, 174326018, ⟨"SECRET", {}, {}, {}⟩⟩, ⟨180879874, 174326274, ⟨"TOP_SECRET", {}, {}, {}⟩⟩]

def policies : List (List PacketPolicy.Rule) := [[⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩], [⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩], [⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩, ⟨[.sourceRange 180879618 180879618, .destinationRange 174326018 174326018, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 201], .allow⟩, ⟨[.sourceRange 174326018 174326018, .destinationRange 180879618 180879618, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 201], .allow⟩], [⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .egress "black", .protocol "esp", .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray", .protocol "esp", .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩, ⟨[.sourceRange 180879874 180879874, .destinationRange 174326274 174326274, .ingress "gray", .egress "black", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .outboundPolicy 202], .allow⟩, ⟨[.sourceRange 174326274 174326274, .destinationRange 180879874 180879874, .ingress "black", .egress "gray", .protocol "udp", .destinationPorts [500, 4500], .ipv4HeaderWords 5, .inboundPolicy 202], .allow⟩]]

lemma ranges_valid : ∀ r ∈ ranges, r.low ≤ r.high := by unfold ranges; decide
lemma ranges_separated : Addressing.Separated ranges := by unfold Addressing.Separated ranges; decide
lemma peers_share_full_level : ∀ p ∈ pairs, Addressing.Owns ranges p.source p.level ∧ Addressing.Owns ranges p.destination p.level := by
  simp [pairs, ranges, Addressing.Owns, Addressing.Contains]
lemma rules_name_intended_peers : ∀ rs ∈ policies, ∀ r ∈ rs, r.verdict = .allow → Targets.RuleNamesPair pairs r := by
  unfold policies pairs
  decide

theorem snapshot_RG014_outer_forwarding : Targets.msc_gray_addressing_for_level_filtering ranges pairs policies :=
  Targets.gray_addressing_of_separated_ranges_and_named_rules ranges pairs policies
    ranges_valid ranges_separated peers_share_full_level rules_name_intended_peers

end TDN.Imported.FreshBaselineAddressing
