import TDN.Targets.EnterpriseGrayFiltering

namespace TDN.Imported.FreshEnterpriseGrayFilters
open TDN.PacketPolicy

def forwardChains : List (List Rule) := [[⟨[.ingress "red", .egress "gray", .outboundPolicy 100], .allow⟩, ⟨[.ingress "gray", .egress "red", .inboundPolicy 100], .allow⟩],
  [⟨[.ingress "red", .egress "gray", .outboundPolicy 100], .allow⟩, ⟨[.ingress "gray", .egress "red", .inboundPolicy 100], .allow⟩],
  [⟨[.ingress "red", .egress "gray", .outboundPolicy 100], .allow⟩, ⟨[.ingress "gray", .egress "red", .inboundPolicy 100], .allow⟩],
  [⟨[.ingress "red", .egress "gray", .outboundPolicy 100], .allow⟩, ⟨[.ingress "gray", .egress "red", .inboundPolicy 100], .allow⟩]]
def inputChains : List (List Rule × TDN.Filter.Verdict) :=
  [([], .allow), ([], .allow), ([], .allow), ([], .allow)]

/-- The four saved FORWARD chains require a matching explicit allow rule.
The conclusion covers first-match filter evaluation, with its saved DROP default. -/
theorem selected_forwarding_requires_an_explicit_allow (rules : List Rule)
    (_member : rules ∈ forwardChains) (packet : Packet) (accepted : Accepts rules packet) :
    ∃ rule ∈ rules, rule.toFilter.accepts packet = true ∧ rule.verdict = .allow := by
  obtain ⟨rule, member, matched, allowed⟩ :=
    TDN.Filter.allowed_has_matching_allow (rules.map Rule.toFilter) packet accepted
  obtain ⟨original, present, rfl⟩ := List.mem_map.mp member
  exact ⟨original, present, matched, allowed⟩

lemma input_defaults_are_acceptance : ∀ chain ∈ inputChains,
    chain.1 = [] ∧ chain.2 = .allow := by decide

/-- The complete saved INPUT chains accept in this selected filter model.
The observation identifies missing local-chain enforcement without inventing a
live arrival trace or asserting that other kernel hooks permit the packet. -/
theorem captured_local_input_accepts_every_packet (chain : List Rule × TDN.Filter.Verdict)
    (member : chain ∈ inputChains) (packet : Packet) :
    TDN.Filter.evaluate (chain.1.map Rule.toFilter) chain.2 packet = .allow := by
  obtain ⟨empty, default⟩ := input_defaults_are_acceptance chain member
  simp [empty, default, TDN.Filter.evaluate]

end TDN.Imported.FreshEnterpriseGrayFilters
