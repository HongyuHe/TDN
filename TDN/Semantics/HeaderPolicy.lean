import TDN.Semantics.PacketPolicy

namespace TDN.PacketPolicy

def ProtocolGuard (allowed : List String) (r : Rule) : Prop :=
  ∃ name ∈ allowed, .protocol name ∈ r.atoms

instance (allowed : List String) (r : Rule) : Decidable (ProtocolGuard allowed r) := by
  unfold ProtocolGuard
  infer_instance

def UnicastGuard (external : String) (low high : Nat) (r : Rule) : Prop :=
  ∃ a ∈ r.atoms, match a with
    | .ingress name => name ≠ external
    | .destinationRange first last => last < low ∨ high < first
    | _ => False

instance (external : String) (low high : Nat) (r : Rule) :
    Decidable (UnicastGuard external low high r) := by
  unfold UnicastGuard
  letI (a : Atom) : Decidable (match a with
    | .ingress name => name ≠ external
    | .destinationRange first last => last < low ∨ high < first
    | _ => False) := by cases a <;> infer_instance
  infer_instance

abbrev Accepts (rules : List Rule) (p : Packet) : Prop :=
  Filter.evaluate (rules.map Rule.toFilter) .deny p = .allow

theorem accepted_protocol (rules : List Rule) (allowed : List String)
    (checked : ∀ r ∈ rules, r.verdict = .allow → ProtocolGuard allowed r)
    (p : Packet) (accepted : Accepts rules p) : p.protocol ∈ allowed := by
  apply Filter.default_deny_sound (rules.map Rule.toFilter) (fun p => p.protocol ∈ allowed) ?_ p accepted
  intro target member allow packet matched
  obtain ⟨r, hr, rfl⟩ := List.mem_map.mp member
  obtain ⟨name, permitted, atom⟩ := checked r hr allow
  have equality : packet.protocol = name := matching_atom matched atom
  exact equality ▸ permitted

theorem accepted_header_words (rules : List Rule) (words : Nat)
    (checked : ∀ r ∈ rules, r.verdict = .allow → .ipv4HeaderWords words ∈ r.atoms)
    (p : Packet) (accepted : Accepts rules p) : p.ipv4HeaderWords = words := by
  apply Filter.default_deny_sound (rules.map Rule.toFilter) (fun p => p.ipv4HeaderWords = words) ?_ p accepted
  intro target member allow packet matched
  obtain ⟨r, hr, rfl⟩ := List.mem_map.mp member
  exact matching_atom matched (checked r hr allow)

theorem accepted_external_unicast (rules : List Rule) (external : String) (low high : Nat)
    (checked : ∀ r ∈ rules, r.verdict = .allow → UnicastGuard external low high r)
    (p : Packet) (accepted : Accepts rules p) (incoming : p.ingress = external) :
    ¬ (low ≤ p.destination ∧ p.destination ≤ high) := by
  have property : p.ingress = external → ¬ (low ≤ p.destination ∧ p.destination ≤ high) := by
    apply Filter.default_deny_sound (rules.map Rule.toFilter)
      (fun p => p.ingress = external → ¬ (low ≤ p.destination ∧ p.destination ≤ high)) ?_ p accepted
    intro target member allow packet matched hIn hMulticast
    obtain ⟨r, hr, rfl⟩ := List.mem_map.mp member
    obtain ⟨a, ha, guard⟩ := checked r hr allow
    have fact := matching_atom matched ha
    cases a <;> simp only at guard <;> try contradiction
    · simp only [Atom.holds] at fact
      omega
    · exact guard (fact.symm.trans hIn)
  exact property incoming

end TDN.PacketPolicy
