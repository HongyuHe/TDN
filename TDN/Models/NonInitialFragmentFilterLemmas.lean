import TDN.Models.DataPlaneForwarding

namespace TDN.FragmentHeaders
open PacketPolicy

def availableWithoutTransport : MatchCondition → Bool
  | .sourcePorts _ | .destinationPorts _ | .icmpType _ | .icmpCode _ | .ipsecUDPFraming | .ipsecUDPFramingWithOptions | .ipsecUDPReplyFramingWithOptions => false
  | _ => true

def rule (r : Rule) : Filter.Rule Packet :=
  ⟨fun packet => r.atoms.all
    (fun atom => availableWithoutTransport atom && decide (atom.matchesPacket packet)), r.verdict⟩

lemma fragment_match_implies_completed_match (r : Rule) (packet : Packet)
    (matched : (rule r).accepts packet = true) : r.toFilter.accepts packet = true := by
  apply List.all_eq_true.mpr
  intro atom member
  exact (Bool.and_eq_true_iff.mp (List.all_eq_true.mp matched atom member)).2

theorem allow_only_rules_cover_noninitial_fragments (rules : List Rule)
    (onlyAllows : ∀ r ∈ rules, r.verdict = .allow)
    (fallback : Filter.Verdict) (packet : Packet)
    (accepted : Filter.evaluate (rules.map rule) fallback packet = .allow) :
    Filter.evaluate (rules.map Rule.toFilter) fallback packet = .allow := by
  induction rules with
  | nil => exact accepted
  | cons first rest ih =>
    simp only [List.map_cons, Filter.evaluate]
    split
    next matched => exact onlyAllows first (by simp)
    next missed =>
      have noFragment : (rule first).accepts packet = false :=
        Bool.eq_false_iff.mpr (fun matched => missed (fragment_match_implies_completed_match first packet matched))
      simp only [List.map_cons, Filter.evaluate, noFragment, Bool.false_eq_true, ↓reduceIte] at accepted
      exact ih (fun r member => onlyAllows r (List.mem_cons_of_mem _ member)) accepted

theorem fragment_forwarding_inherits_packet_policy (rules : List Rule)
    (onlyAllows : ∀ r ∈ rules, r.verdict = .allow) (inside outside : String)
    (guards : ∀ r ∈ rules, r.verdict = .allow → RequiresIpsecPolicyMatch r inside outside)
    (packet : Packet)
    (accepted : Filter.evaluate (rules.map rule) .deny packet = .allow) :
    ProtectedForward inside outside packet :=
  forwarding_policy_protects rules inside outside guards packet
    (allow_only_rules_cover_noninitial_fragments rules onlyAllows .deny packet accepted)

def completeTransport (packet : Packet) (sourcePort destinationPort kind code : Nat) : Packet :=
  { packet with
    sourcePort := sourcePort
    destinationPort := destinationPort
    icmpType := kind
    icmpCode := code }

lemma fragment_rule_ignores_unavailable_transport (r : Rule) (packet : Packet)
    (sourcePort destinationPort kind code : Nat) :
    (rule r).accepts (completeTransport packet sourcePort destinationPort kind code) =
    (rule r).accepts packet := by
  have same :
      (fun atom => availableWithoutTransport atom &&
        decide (atom.matchesPacket (completeTransport packet sourcePort destinationPort kind code))) =
      (fun atom => availableWithoutTransport atom && decide (atom.matchesPacket packet)) := by
    funext atom
    cases atom <;> rfl
  exact congrArg (fun predicate => r.atoms.all predicate) same

theorem every_transport_completion_covers_accepted_fragment (rules : List Rule)
    (onlyAllows : ∀ r ∈ rules, r.verdict = .allow)
    (fallback : Filter.Verdict) (packet : Packet)
    (accepted : Filter.evaluate (rules.map rule) fallback packet = .allow)
    (sourcePort destinationPort kind code : Nat) :
    Filter.evaluate (rules.map Rule.toFilter) fallback
      (completeTransport packet sourcePort destinationPort kind code) = .allow := by
  have same : Filter.evaluate (rules.map rule) fallback
      (completeTransport packet sourcePort destinationPort kind code) =
      Filter.evaluate (rules.map rule) fallback packet := by
    clear onlyAllows accepted
    induction rules with
    | nil => rfl
    | cons first rest ih =>
      simp only [List.map_cons, Filter.evaluate, fragment_rule_ignores_unavailable_transport]
      rw [ih]
  exact allow_only_rules_cover_noninitial_fragments rules onlyAllows fallback _ (same.trans accepted)

lemma route_selection_ignores_unavailable_transport (routes : List DataPlaneForwarding.FibRoute)
    (route : DataPlaneForwarding.FibRoute) (packet : Packet) (sourcePort destinationPort kind code : Nat) :
    DataPlaneForwarding.SelectedFibRoute routes route
      (completeTransport packet sourcePort destinationPort kind code) ↔
    DataPlaneForwarding.SelectedFibRoute routes route packet := Iff.rfl

lemma policy_selection_ignores_unavailable_transport (policies : List DataPlaneForwarding.IpsecPolicy)
    (packet : Packet) (sourcePort destinationPort kind code : Nat) :
    DataPlaneForwarding.lookupSpdPolicies policies
      (completeTransport packet sourcePort destinationPort kind code) =
    DataPlaneForwarding.lookupSpdPolicies policies packet := rfl

end TDN.FragmentHeaders
