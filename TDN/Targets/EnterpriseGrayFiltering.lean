import TDN.Semantics.HeaderPolicy

namespace TDN.Targets.EnterpriseGray

open TDN.PacketPolicy

/-- A source range associated with the interface where packets may enter.
The association must come from the applicable network and route evidence. -/
structure SourceRange where
  ingress : String
  low : Nat
  high : Nat
  deriving DecidableEq, Repr

def KnownIngressSource (ranges : List SourceRange) (packet : Packet) : Prop :=
  ∃ range ∈ ranges, packet.ingress = range.ingress ∧
    range.low ≤ packet.source ∧ packet.source ≤ range.high

/-- One accepting rule must bind its source range to the same input interface.
Separate lists of permitted addresses and interfaces would lose that pairing. -/
def RuleSourceCheck (ranges : List SourceRange) (rule : Rule) : Prop :=
  ∃ range ∈ ranges, .ingress range.ingress ∈ rule.atoms ∧
    ∃ atom ∈ rule.atoms, match atom with
      | .sourceRange low high => range.low ≤ low ∧ high ≤ range.high
      | _ => False

instance (ranges : List SourceRange) (rule : Rule) :
    Decidable (RuleSourceCheck ranges rule) := by
  unfold RuleSourceCheck
  letI (range : SourceRange) (atom : Atom) : Decidable (match atom with
    | .sourceRange low high => range.low ≤ low ∧ high ≤ range.high
    | _ => False) := by cases atom <;> infer_instance
  infer_instance

lemma matched_source_is_known (ranges : List SourceRange) (rule : Rule)
    (checked : RuleSourceCheck ranges rule) (packet : Packet)
    (matched : rule.toFilter.accepts packet = true) : KnownIngressSource ranges packet := by
  obtain ⟨range, present, ingress, atom, member, bounds⟩ := checked
  have sameIngress : packet.ingress = range.ingress := matching_atom matched ingress
  have sourceFact := matching_atom matched member
  refine ⟨range, present, sameIngress, ?_⟩
  cases atom <;> simp only at bounds <;> try contradiction
  simp only [Atom.holds] at sourceFact
  omega

/-- EG-FW-3 and EG-FW-11 restrict addresses according to the receiving interface.
EG-FW-4 and EG-FW-12 supply the default-deny behavior for the selected chains.
The complete chain inventory and the meaning of each known range remain evidence
obligations. Positive allowances elsewhere in the annex are separate obligations. -/
def ingress_source_filtering (ranges : List SourceRange) (rules : List Rule) : Prop :=
  ∀ packet, Accepts rules packet → KnownIngressSource ranges packet

theorem source_filtering_from_rule_checks (ranges : List SourceRange) (rules : List Rule)
    (checked : ∀ rule ∈ rules, rule.verdict = .allow → RuleSourceCheck ranges rule) :
    ingress_source_filtering ranges rules := by
  intro packet accepted
  apply TDN.Filter.default_deny_sound (rules.map Rule.toFilter)
    (KnownIngressSource ranges) ?_ packet accepted
  intro target member allow candidate matched
  obtain ⟨rule, present, rfl⟩ := List.mem_map.mp member
  exact matched_source_is_known ranges rule (checked rule present allow) candidate matched

theorem unknown_source_pair_is_denied (ranges : List SourceRange) (rules : List Rule)
    (checked : ∀ rule ∈ rules, rule.verdict = .allow → RuleSourceCheck ranges rule)
    (packet : Packet) (unknown : ¬ KnownIngressSource ranges packet) :
    TDN.Filter.evaluate (rules.map Rule.toFilter) .deny packet = .deny := by
  have rejected : ¬ Accepts rules packet :=
    fun accepted => unknown (source_filtering_from_rule_checks ranges rules checked packet accepted)
  cases result : TDN.Filter.evaluate (rules.map Rule.toFilter) .deny packet with
  | deny => rfl
  | allow => exact False.elim (rejected result)

def RuleManagementIngressCheck (ports : List String) (rule : Rule) : Prop :=
  ∃ port ∈ ports, .ingress port ∈ rule.atoms

instance (ports : List String) (rule : Rule) :
    Decidable (RuleManagementIngressCheck ports rule) := by
  unfold RuleManagementIngressCheck
  infer_instance

/-- EG-FW-1 restricts the physical interfaces used for management access.
The supplied chain must include every applicable management access rule. -/
theorem management_ingress_from_rule_checks (ports : List String) (rules : List Rule)
    (checked : ∀ rule ∈ rules, rule.verdict = .allow → RuleManagementIngressCheck ports rule)
    (packet : Packet) (accepted : Accepts rules packet) : packet.ingress ∈ ports := by
  apply TDN.Filter.default_deny_sound (rules.map Rule.toFilter)
    (fun p => p.ingress ∈ ports) ?_ packet accepted
  intro target member allow candidate matched
  obtain ⟨rule, present, rfl⟩ := List.mem_map.mp member
  obtain ⟨port, permitted, atom⟩ := checked rule present allow
  have equality : candidate.ingress = port := matching_atom matched atom
  exact equality ▸ permitted

end TDN.Targets.EnterpriseGray
