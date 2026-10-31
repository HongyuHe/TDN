import TDN.Semantics.ExecutionInvariant
import Lean.Elab.Tactic.Omega

namespace TDN.Execution

def PortCompatible (rule : PacketPolicy.Rule) (ingress egress : String) : Prop :=
  ∀ atom ∈ rule.atoms, match atom with
    | .ingress name => name = ingress
    | .egress name => name = egress
    | _ => True

def ImpossibleAuthentication (rule : PacketPolicy.Rule) (authenticated : List Nat) : Prop :=
  ∃ atom ∈ rule.atoms, match atom with
    | .inboundPolicy id => id ∉ authenticated
    | _ => False

def HasOutboundGuard (rule : PacketPolicy.Rule) : Prop :=
  ∃ atom ∈ rule.atoms, match atom with
    | .outboundPolicy _ => True
    | _ => False

def ExcludesSelector (rule : PacketPolicy.Rule) (association : Association) : Prop :=
  ∃ atom ∈ rule.atoms, match atom with
    | .sourceRange low high => high < association.sourceLow ∨ association.sourceHigh < low
    | .destinationRange low high =>
        high < association.destinationLow ∨ association.destinationHigh < low
    | _ => False

instance (r : PacketPolicy.Rule) (i o : String) : Decidable (PortCompatible r i o) := by
  unfold PortCompatible
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .ingress n => n = i | .egress n => n = o | _ => True) := by cases a <;> infer_instance
  infer_instance

instance (r : PacketPolicy.Rule) (auth : List Nat) :
    Decidable (ImpossibleAuthentication r auth) := by
  unfold ImpossibleAuthentication
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .inboundPolicy n => n ∉ auth | _ => False) := by cases a <;> infer_instance
  infer_instance

instance (r : PacketPolicy.Rule) : Decidable (HasOutboundGuard r) := by
  unfold HasOutboundGuard
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .outboundPolicy _ => True | _ => False) := by cases a <;> infer_instance
  infer_instance

instance (r : PacketPolicy.Rule) (p : Association) : Decidable (ExcludesSelector r p) := by
  unfold ExcludesSelector
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .sourceRange l h => h < p.sourceLow ∨ p.sourceHigh < l
    | .destinationRange l h => h < p.destinationLow ∨ p.destinationHigh < l
    | _ => False) := by cases a <;> infer_instance
  infer_instance

lemma matched_ports_compatible {rule : PacketPolicy.Rule} {packet : PacketPolicy.Packet}
    (matched : rule.toFilter.accepts packet = true) :
    PortCompatible rule packet.ingress packet.egress := by
  intro atom member
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp_all [PacketPolicy.Atom.holds]

lemma matching_authentication_possible {rule : PacketPolicy.Rule}
    {packet : PacketPolicy.Packet} (matched : rule.toFilter.accepts packet = true) :
    ¬ ImpossibleAuthentication rule packet.inboundPolicies := by
  rintro ⟨atom, member, impossible⟩
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp_all [PacketPolicy.Atom.holds]

lemma excluded_selector_cannot_match {rule : PacketPolicy.Rule}
    {packet : PacketPolicy.Packet} {association : Association}
    (excluded : ExcludesSelector rule association)
    (matched : rule.toFilter.accepts packet = true) :
    association.matches packet = false := by
  obtain ⟨atom, member, disjoint⟩ := excluded
  have holds := PacketPolicy.matching_atom matched member
  unfold Association.matches
  apply decide_eq_false
  cases atom <;> simp only at disjoint <;> try contradiction
  all_goals simp only [PacketPolicy.Atom.holds] at holds; omega

def RuleStackCheck (c : Config) (layout : Nat → List Nat)
    (entry port : Nat) (authenticated : List Nat) (rule : PacketPolicy.Rule) : Prop :=
  ¬ PortCompatible rule (c.interfaceName entry) (c.interfaceName port) ∨
  ImpossibleAuthentication rule authenticated ∨
  ((HasOutboundGuard rule ∨ processingStack layout entry authenticated = layout port) ∧
    ∀ association ∈ c.outbound port, ExcludesSelector rule association ∨
      association.tag :: processingStack layout entry authenticated = layout port)

lemma checked_rule_stack_effect {c : Config} {layout : Nat → List Nat}
    {port : Nat} {frame : Frame} {authenticated : List Nat} {rule : PacketPolicy.Rule}
    (ingress : frame.packet.ingress = c.interfaceName frame.enteredPort)
    (checked : RuleStackCheck c layout frame.enteredPort port authenticated rule)
    (matched : rule.toFilter.accepts (policyPacket c port frame authenticated) = true) :
    (selectedAssociations (c.outbound port) frame.packet = [] →
      processingStack layout frame.enteredPort authenticated = layout port) ∧
    (∀ association ∈ selectedAssociations (c.outbound port) frame.packet,
      association.tag :: processingStack layout frame.enteredPort authenticated = layout port) := by
  have ports := matched_ports_compatible matched
  have auth := matching_authentication_possible matched
  rcases checked with incompatible | impossible | ⟨plain, encryption⟩
  · exact False.elim (incompatible (by simpa [policyPacket, ingress] using ports))
  · exact False.elim (auth impossible)
  · constructor
    · intro empty
      rcases plain with guard | same
      · obtain ⟨atom, member, kind⟩ := guard
        cases atom <;> simp only at kind <;> try contradiction
        exact False.elim (outbound_policy_atom_excludes_plain c port frame authenticated member matched empty)
      · exact same
    · intro association selected
      obtain ⟨configured, selector⟩ := matched_policy_is_configured selected
      rcases encryption association configured with excluded | same
      · have impossible := excluded_selector_cannot_match excluded matched
        have sameMatch : association.matches (policyPacket c port frame authenticated) =
            association.matches frame.packet := rfl
        rw [sameMatch, selector] at impossible
        contradiction
      · exact same

theorem checked_hook_stack_effect (c : Config) (layout : Nat → List Nat)
    (rules : List PacketPolicy.Rule) (port : Nat) (frame : Frame) (authenticated : List Nat)
    (ingress : frame.packet.ingress = c.interfaceName frame.enteredPort)
    (checked : ∀ rule ∈ rules, rule.verdict = .allow →
      RuleStackCheck c layout frame.enteredPort port authenticated rule)
    (accepted : accepts rules .deny (policyPacket c port frame authenticated)) :
    (selectedAssociations (c.outbound port) frame.packet = [] →
      processingStack layout frame.enteredPort authenticated = layout port) ∧
    (∀ association ∈ selectedAssociations (c.outbound port) frame.packet,
      association.tag :: processingStack layout frame.enteredPort authenticated = layout port) := by
  obtain ⟨filtered, member, matched, allow⟩ :=
    Filter.allowed_has_matching_allow _ _ accepted
  obtain ⟨rule, inRules, rfl⟩ := List.mem_map.mp member
  exact checked_rule_stack_effect ingress (checked rule inRules allow) matched

end TDN.Execution
