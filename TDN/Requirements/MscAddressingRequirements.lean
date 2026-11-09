import TDN.Models.DisjointAddressRanges
import TDN.Models.IpsecAndAclRuleModel
import TDN.Requirements.TwoLayerOverlayArchitecture

namespace TDN.Requirements

structure IntendedAddressPair where
  source : Nat
  destination : Nat
  level : SecurityLevel
  deriving DecidableEq

def IntendedPair (pairs : List IntendedAddressPair) (packet : PacketPolicy.Packet) : Prop :=
  ∃ pair ∈ pairs, packet.source = pair.source ∧ packet.destination = pair.destination

def RuleNamesPair (pairs : List IntendedAddressPair) (rule : PacketPolicy.Rule) : Prop :=
  ∃ pair ∈ pairs,
    .sourceRange pair.source pair.source ∈ rule.atoms ∧
    .destinationRange pair.destination pair.destination ∈ rule.atoms

instance (pairs : List IntendedAddressPair) (rule : PacketPolicy.Rule) :
    Decidable (RuleNamesPair pairs rule) := by
  unfold RuleNamesPair
  infer_instance

lemma named_pair_rule_matches_intended {pairs : List IntendedAddressPair}
    {rule : PacketPolicy.Rule} {packet : PacketPolicy.Packet}
    (guard : RuleNamesPair pairs rule) (matched : rule.toFilter.accepts packet = true) :
    IntendedPair pairs packet := by
  obtain ⟨pair, member, hs, hd⟩ := guard
  have source := PacketPolicy.matching_atom matched hs
  have destination := PacketPolicy.matching_atom matched hd
  change pair.source ≤ packet.source ∧ packet.source ≤ pair.source at source
  change pair.destination ≤ packet.destination ∧ packet.destination ≤ pair.destination at destination
  exact ⟨pair, member, by omega, by omega⟩

def msc_gray_addressing_for_level_filtering
    (ranges : List (Addressing.Range SecurityLevel)) (pairs : List IntendedAddressPair)
    (policies : List (List PacketPolicy.Rule)) : Prop :=
  (∀ range ∈ ranges, range.low ≤ range.high) ∧
  (∀ address a b, Addressing.Owns ranges address a →
    Addressing.Owns ranges address b → a = b) ∧
  (∀ pair ∈ pairs, Addressing.Owns ranges pair.source pair.level ∧
    Addressing.Owns ranges pair.destination pair.level) ∧
  (∀ rules ∈ policies, ∀ packet,
    Filter.evaluate (rules.map PacketPolicy.Rule.toFilter) .deny packet = .allow →
    IntendedPair pairs packet)

theorem gray_addressing_of_separated_ranges_and_named_rules
    (ranges : List (Addressing.Range SecurityLevel)) (pairs : List IntendedAddressPair)
    (policies : List (List PacketPolicy.Rule))
    (valid : ∀ range ∈ ranges, range.low ≤ range.high)
    (separated : Addressing.Separated ranges)
    (peers : ∀ pair ∈ pairs, Addressing.Owns ranges pair.source pair.level ∧
      Addressing.Owns ranges pair.destination pair.level)
    (rulesChecked : ∀ rules ∈ policies, ∀ rule ∈ rules,
      rule.verdict = .allow → RuleNamesPair pairs rule) :
    msc_gray_addressing_for_level_filtering ranges pairs policies := by
  refine ⟨valid, ?_, peers, ?_⟩
  · intro address a b ha hb
    exact Addressing.separated_ranges_unique_label separated ha hb
  · intro rules present packet accepted
    apply Filter.default_deny_sound (rules.map PacketPolicy.Rule.toFilter)
      (IntendedPair pairs) ?_ packet accepted
    intro rule inRules allow p matched
    obtain ⟨source, member, rfl⟩ := List.mem_map.mp inRules
    exact named_pair_rule_matches_intended (rulesChecked rules present source member allow) matched

end TDN.Requirements
