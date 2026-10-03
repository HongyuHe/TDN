import Std

/-!
An ACCEPT-only table lifts local rule guarantees to all accepted packets.
The packet and rule types are parameters, so the theorem applies to input,
forwarding, output, or another explicitly modeled decision point. Rules with
different actions require an ordered first-match semantics and a separate proof.
-/
namespace TDN.Network.Filter
universe u v

def accepts {Rule : Type u} {Packet : Type v}
    (matchRule : Rule → Packet → Bool) (rules : List Rule)
    (defaultAccept : Bool) (packet : Packet) : Bool :=
  rules.any (fun rule => matchRule rule packet) || defaultAccept

/-- Every accepted packet has a matching rule when the default is DROP.
No enumeration of packets is required. -/
theorem accepted_has_rule {Rule : Type u} {Packet : Type v}
    (matchRule : Rule → Packet → Bool) (rules : List Rule) (packet : Packet)
    (accepted : accepts matchRule rules false packet = true) :
    ∃ rule ∈ rules, matchRule rule packet = true := by
  simpa [accepts] using accepted

/-- A local rule implication becomes a guarantee for the entire table.
The premise can be proved from finite structural certificates for every rule. -/
theorem accepted_satisfies {Rule : Type u} {Packet : Type v}
    (matchRule : Rule → Packet → Bool) (rules : List Rule) (safe : Packet → Prop)
    (ruleInvariant : ∀ rule ∈ rules, ∀ packet, matchRule rule packet = true → safe packet)
    (packet : Packet) (accepted : accepts matchRule rules false packet = true) : safe packet := by
  obtain ⟨rule, member, matched⟩ := accepted_has_rule matchRule rules packet accepted
  exact ruleInvariant rule member packet matched

/-- Rejection by every rule lifts to rejection by a default-deny table. -/
theorem all_rules_reject {Rule : Type u} {Packet : Type v}
    (matchRule : Rule → Packet → Bool) (rules : List Rule) (packet : Packet)
    (rejected : ∀ rule ∈ rules, matchRule rule packet = false) :
    accepts matchRule rules false packet = false := by
  simp only [accepts, Bool.or_false]
  apply List.any_eq_false.mpr
  intro rule member
  rw [rejected rule member]
  decide

/-- Rule permutation preserves ACCEPT-only behavior, including a default
policy. That premise is essential when comparing normalized rule exports. -/
theorem permutation_preserves {Rule : Type u} {Packet : Type v}
    (matchRule : Rule → Packet → Bool) {a b : List Rule} (same : a.Perm b)
    (defaultAccept : Bool) (packet : Packet) :
    accepts matchRule a defaultAccept packet = accepts matchRule b defaultAccept packet := by
  unfold accepts
  rw [List.Perm.any_eq same]

end TDN.Network.Filter
