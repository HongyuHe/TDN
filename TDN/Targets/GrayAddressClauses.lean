import TDN.Targets.Addressing
import TDN.Semantics.HeaderPolicy

namespace TDN.Targets

theorem accepted_named_peer_addresses_share_level
    (ranges : List (Addressing.Range SecurityLevel)) (pairs : List IntendedAddressPair)
    (rules : List PacketPolicy.Rule)
    (peers : ∀ pair ∈ pairs, Addressing.Owns ranges pair.source pair.level ∧
      Addressing.Owns ranges pair.destination pair.level)
    (checked : ∀ rule ∈ rules, rule.verdict = .allow → RuleNamesPair pairs rule)
    (packet : PacketPolicy.Packet) (accepted : PacketPolicy.Accepts rules packet) :
    ∃ level, Addressing.Owns ranges packet.source level ∧
      Addressing.Owns ranges packet.destination level := by
  have intended : IntendedPair pairs packet := by
    apply Filter.default_deny_sound (rules.map PacketPolicy.Rule.toFilter)
      (IntendedPair pairs) ?_ packet accepted
    intro target member allow candidate matched
    obtain ⟨rule, present, rfl⟩ := List.mem_map.mp member
    exact named_pair_rule_matches_intended (checked rule present allow) matched
  obtain ⟨pair, member, source, destination⟩ := intended
  exact ⟨pair.level, source ▸ (peers pair member).1, destination ▸ (peers pair member).2⟩

theorem different_level_addresses_are_denied
    (ranges : List (Addressing.Range SecurityLevel)) (pairs : List IntendedAddressPair)
    (rules : List PacketPolicy.Rule) (separated : Addressing.Separated ranges)
    (peers : ∀ pair ∈ pairs, Addressing.Owns ranges pair.source pair.level ∧
      Addressing.Owns ranges pair.destination pair.level)
    (checked : ∀ rule ∈ rules, rule.verdict = .allow → RuleNamesPair pairs rule)
    (packet : PacketPolicy.Packet) (sourceLevel destinationLevel : SecurityLevel)
    (source : Addressing.Owns ranges packet.source sourceLevel)
    (destination : Addressing.Owns ranges packet.destination destinationLevel)
    (different : sourceLevel ≠ destinationLevel) :
    Filter.evaluate (rules.map PacketPolicy.Rule.toFilter) .deny packet = .deny := by
  cases verdict : Filter.evaluate (rules.map PacketPolicy.Rule.toFilter) .deny packet with
  | deny => rfl
  | allow =>
    obtain ⟨level, sourceOwned, destinationOwned⟩ :=
      accepted_named_peer_addresses_share_level ranges pairs rules peers checked packet verdict
    exact False.elim (different ((Addressing.separated_ranges_unique_label separated source sourceOwned).trans
      (Addressing.separated_ranges_unique_label separated destination destinationOwned).symm))

end TDN.Targets
