import TDN.Models.IpsecAndAclRuleModel

namespace TDN.PacketPolicy

def ProtocolGuard (allowed : List String) (r : PacketAclRule) : Prop :=
  ∃ name ∈ allowed, .protocol name ∈ r.atoms

instance (allowed : List String) (r : PacketAclRule) : Decidable (ProtocolGuard allowed r) := by
  unfold ProtocolGuard
  infer_instance

def UnicastGuard (external : String) (low high : Nat) (r : PacketAclRule) : Prop :=
  ∃ a ∈ r.atoms, match a with
    | .ingress name => name ≠ external
    | .destinationRange first last => last < low ∨ high < first
    | _ => False

instance (external : String) (low high : Nat) (r : PacketAclRule) :
    Decidable (UnicastGuard external low high r) := by
  unfold UnicastGuard
  letI (a : MatchCondition) : Decidable (match a with
    | .ingress name => name ≠ external
    | .destinationRange first last => last < low ∨ high < first
    | _ => False) := by cases a <;> infer_instance
  infer_instance

abbrev DefaultDenyAllows (rules : List PacketAclRule) (p : Packet) : Prop :=
  AclAllows rules .deny p

theorem accepted_protocol (rules : List PacketAclRule) (allowed : List String)
    (checked : ∀ r ∈ rules, r.verdict = .allow → ProtocolGuard allowed r)
    (p : Packet) (accepted : DefaultDenyAllows rules p) : p.protocol ∈ allowed := by
  apply Filter.default_deny_sound (rules.map PacketAclRule.toFilter) (fun p => p.protocol ∈ allowed) ?_ p accepted
  intro target member allow packet matched
  obtain ⟨r, hr, rfl⟩ := List.mem_map.mp member
  obtain ⟨name, permitted, atom⟩ := checked r hr allow
  have equality : packet.protocol = name := matching_atom matched atom
  exact equality ▸ permitted

def ImmediateHeaderGuard (allowed : List Nat) (rule : PacketAclRule) : Prop :=
  .ipv6NextHeaders allowed ∈ rule.atoms

instance (allowed : List Nat) (rule : PacketAclRule) : Decidable (ImmediateHeaderGuard allowed rule) := by
  unfold ImmediateHeaderGuard
  infer_instance

theorem accepted_immediate_header (rules : List PacketAclRule) (allowed : List Nat)
    (checked : ∀ r ∈ rules, r.verdict = .allow → ImmediateHeaderGuard allowed r)
    (p : Packet) (accepted : DefaultDenyAllows rules p) : p.ipv6NextHeader ∈ allowed := by
  apply Filter.default_deny_sound (rules.map PacketAclRule.toFilter)
    (fun p => p.ipv6NextHeader ∈ allowed) ?_ p accepted
  intro target member allow packet matched
  obtain ⟨r, hr, rfl⟩ := List.mem_map.mp member
  exact matching_atom matched (checked r hr allow)

theorem accepted_header_words (rules : List PacketAclRule) (words : Nat)
    (checked : ∀ r ∈ rules, r.verdict = .allow → .ipv4HeaderWords words ∈ r.atoms)
    (p : Packet) (accepted : DefaultDenyAllows rules p) : p.ipv4HeaderWords = words := by
  apply Filter.default_deny_sound (rules.map PacketAclRule.toFilter) (fun p => p.ipv4HeaderWords = words) ?_ p accepted
  intro target member allow packet matched
  obtain ⟨r, hr, rfl⟩ := List.mem_map.mp member
  exact matching_atom matched (checked r hr allow)

theorem accepted_external_unicast (rules : List PacketAclRule) (external : String) (low high : Nat)
    (checked : ∀ r ∈ rules, r.verdict = .allow → UnicastGuard external low high r)
    (p : Packet) (accepted : DefaultDenyAllows rules p) (incoming : p.ingress = external) :
    ¬ (low ≤ p.destination ∧ p.destination ≤ high) := by
  have property : p.ingress = external → ¬ (low ≤ p.destination ∧ p.destination ≤ high) := by
    apply Filter.default_deny_sound (rules.map PacketAclRule.toFilter)
      (fun p => p.ingress = external → ¬ (low ≤ p.destination ∧ p.destination ≤ high)) ?_ p accepted
    intro target member allow packet matched hIn hMulticast
    obtain ⟨r, hr, rfl⟩ := List.mem_map.mp member
    obtain ⟨a, ha, guard⟩ := checked r hr allow
    have fact := matching_atom matched ha
    cases a <;> simp only at guard <;> try contradiction
    · simp only [MatchCondition.matchesPacket] at fact
      omega
    · exact guard (fact.symm.trans hIn)
  exact property incoming

end TDN.PacketPolicy
