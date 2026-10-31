import TDN.Semantics.Filter

namespace TDN.PacketPolicy

structure Packet where
  source : Nat
  destination : Nat
  protocol : String
  ingress : String
  egress : String
  sourcePort : Nat
  destinationPort : Nat
  ipv4HeaderWords : Nat
  inboundPolicies : List Nat
  outboundPolicies : List Nat
  connectionState : String

inductive Atom where
  | sourceRange (low high : Nat)
  | destinationRange (low high : Nat)
  | protocol (name : String)
  | ingress (name : String)
  | egress (name : String)
  | sourcePorts (ports : List Nat)
  | destinationPorts (ports : List Nat)
  | ipv4HeaderWords (words : Nat)
  | inboundPolicy (requestId : Nat)
  | outboundPolicy (requestId : Nat)
  | connectionStates (states : List String)
  deriving DecidableEq, Repr

def Atom.holds : Atom → Packet → Prop
  | .sourceRange low high, p => low ≤ p.source ∧ p.source ≤ high
  | .destinationRange low high, p => low ≤ p.destination ∧ p.destination ≤ high
  | .protocol name, p => p.protocol = name
  | .ingress name, p => p.ingress = name
  | .egress name, p => p.egress = name
  | .sourcePorts ports, p => p.sourcePort ∈ ports
  | .destinationPorts ports, p => p.destinationPort ∈ ports
  | .ipv4HeaderWords words, p => p.ipv4HeaderWords = words
  | .inboundPolicy id, p => id ∈ p.inboundPolicies
  | .outboundPolicy id, p => id ∈ p.outboundPolicies
  | .connectionStates states, p => p.connectionState ∈ states

instance (a : Atom) (p : Packet) : Decidable (a.holds p) := by
  cases a <;> unfold Atom.holds <;> infer_instance

structure Rule where
  atoms : List Atom
  verdict : Filter.Verdict
  deriving DecidableEq, Repr

def Rule.toFilter (r : Rule) : Filter.Rule Packet :=
  ⟨fun p => r.atoms.all (fun a => decide (a.holds p)), r.verdict⟩

theorem matching_atom {r : Rule} {p : Packet}
    (matched : r.toFilter.accepts p = true) {a : Atom} (member : a ∈ r.atoms) :
    a.holds p := by
  have all := List.all_eq_true.mp matched
  exact of_decide_eq_true (all a member)

def OutboundGuard (r : Rule) (inside outside : String) : Prop :=
  .ingress inside ∈ r.atoms ∧ .egress outside ∈ r.atoms ∧
  ∃ a ∈ r.atoms, match a with | .outboundPolicy _ => True | _ => False

def InboundGuard (r : Rule) (inside outside : String) : Prop :=
  .ingress outside ∈ r.atoms ∧ .egress inside ∈ r.atoms ∧
  ∃ a ∈ r.atoms, match a with | .inboundPolicy _ => True | _ => False

def Guarded (r : Rule) (inside outside : String) : Prop :=
  OutboundGuard r inside outside ∨ InboundGuard r inside outside

instance (r : Rule) (inside outside : String) : Decidable (Guarded r inside outside) := by
  unfold Guarded OutboundGuard InboundGuard
  letI dout (a : Atom) : Decidable (match a with | .outboundPolicy _ => True | _ => False) := by
    cases a <;> infer_instance
  letI din (a : Atom) : Decidable (match a with | .inboundPolicy _ => True | _ => False) := by
    cases a <;> infer_instance
  infer_instance

def ProtectedForward (inside outside : String) (p : Packet) : Prop :=
  (p.ingress = inside ∧ p.egress = outside ∧ ∃ id, id ∈ p.outboundPolicies) ∨
  (p.ingress = outside ∧ p.egress = inside ∧ ∃ id, id ∈ p.inboundPolicies)

theorem guarded_rule_protects {r : Rule} {inside outside : String} {p : Packet}
    (guard : Guarded r inside outside) (matched : r.toFilter.accepts p = true) :
    ProtectedForward inside outside p := by
  rcases guard with ⟨hin, hout, a, ha, hkind⟩ | ⟨hin, hout, a, ha, hkind⟩
  · have pi : p.ingress = inside := matching_atom matched hin
    have po : p.egress = outside := matching_atom matched hout
    have policyEvidence := matching_atom matched ha
    cases a <;> simp only at hkind <;> try contradiction
    exact Or.inl ⟨pi, po, _, policyEvidence⟩
  · have pi : p.ingress = outside := matching_atom matched hin
    have po : p.egress = inside := matching_atom matched hout
    have policyEvidence := matching_atom matched ha
    cases a <;> simp only at hkind <;> try contradiction
    exact Or.inr ⟨pi, po, _, policyEvidence⟩

/-- Concrete first-match rules imply IPsec policy membership for every accepted packet. -/
theorem forwarding_policy_protects (rules : List Rule) (inside outside : String)
    (checked : ∀ r ∈ rules, r.verdict = .allow → Guarded r inside outside)
    (p : Packet) (accepted : Filter.evaluate (rules.map Rule.toFilter) .deny p = .allow) :
    ProtectedForward inside outside p := by
  apply Filter.default_deny_sound (rules.map Rule.toFilter) (ProtectedForward inside outside) ?_ p accepted
  intro r hr allow packet matched
  obtain ⟨source, hsource, rfl⟩ := List.mem_map.mp hr
  exact guarded_rule_protects (checked source hsource allow) matched

end TDN.PacketPolicy
