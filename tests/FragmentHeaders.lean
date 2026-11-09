import TDN.Models.NonInitialFragmentFilterLemmas
open TDN PacketPolicy

def testPacket : Packet :=
  { source := 10, destination := 20, protocol := "tcp", ingress := "in", egress := "out",
    sourcePort := 1234, destinationPort := 80, ipv4HeaderWords := 5,
    matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "NEW" }

-- A noninitial fragment never supplies a TCP port through the abstract record.
example : (FragmentHeaders.rule ⟨[.destinationPorts [80]], .allow⟩).accepts testPacket = false := by
  decide

-- IP-level source and protocol checks still apply to noninitial fragments.
example : (FragmentHeaders.rule ⟨[.sourceRange 10 10, .protocol "tcp"], .allow⟩).accepts
    testPacket = true := by decide

-- An earlier port-specific denial shows why allow-only evidence is required.
def unsafeCompletionRules : List Rule :=
  [⟨[.destinationPorts [80]], .deny⟩, ⟨[], .allow⟩]

example : Filter.evaluate (unsafeCompletionRules.map FragmentHeaders.rule) .deny testPacket = .allow ∧
    Filter.evaluate (unsafeCompletionRules.map Rule.toFilter) .deny testPacket = .deny := by
  decide
