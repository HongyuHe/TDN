import TDN.Models.IndexedWitnessTree
import TDN.Models.AclFlowCoverageMasks

/-! An allow-rule witness includes checked exclusions for every earlier deny rule. -/
namespace TDN.PacketPolicy
open Certificates

structure AclRuleIndex where
  earlierRules : List Rule
  allowed : WitnessTree Rule
  deriving DecidableEq

structure AclPermitWitness where
  ruleIndex : List Bool
  rejectedAtoms : List Nat
  deriving DecidableEq

def AclRuleIndex.rules (index : AclRuleIndex) : List Rule := index.earlierRules ++ index.allowed.values

def AclRuleIndex.Valid (index : AclRuleIndex) : Prop :=
  ∀ rule ∈ index.allowed.values, rule.verdict = .allow

instance (index : AclRuleIndex) : Decidable index.Valid := by unfold AclRuleIndex.Valid; infer_instance

def checkAclPrefix (mask : AclFlowSelector) : List Rule → List Nat → Bool
  | [], [] => true
  | rule :: rest, index :: indices =>
      (decide (rule.verdict = .allow) ||
        ((rule.atoms[index]?).map (fun atom => decide (mask.Rejects atom))).getD false) &&
        checkAclPrefix mask rest indices
  | _, _ => false

lemma checked_acl_prefix_is_safe (mask : AclFlowSelector) (rules : List Rule) (indices : List Nat)
    (checked : checkAclPrefix mask rules indices = true) :
    ∀ rule ∈ rules, rule.verdict = .allow ∨ ∃ atom ∈ rule.atoms, mask.Rejects atom := by
  induction rules generalizing indices with
  | nil => simp
  | cons rule rest ih =>
    cases indices with
    | nil => simp [checkAclPrefix] at checked
    | cons index indices =>
      have parts := Bool.and_eq_true_iff.mp checked
      have head : rule.verdict = .allow ∨ ∃ atom ∈ rule.atoms, mask.Rejects atom := by
        rcases Bool.or_eq_true_iff.mp parts.1 with allowed | rejected
        · exact Or.inl (of_decide_eq_true allowed)
        · cases found : rule.atoms[index]? with
          | none => simp [found] at rejected
          | some atom =>
            exact Or.inr ⟨atom, List.mem_of_getElem? found, of_decide_eq_true (by simpa [found] using rejected)⟩
      simpa only [List.forall_mem_cons] using And.intro head (ih indices parts.2)

lemma allow_only_rules_permit (mask : AclFlowSelector) (rules : List Rule)
    (allowed : ∀ rule ∈ rules, rule.verdict = .allow)
    (witness : ∃ rule ∈ rules, ∀ atom ∈ rule.atoms, mask.Allows atom) :
    mask.IsPermittedByAclChain rules := by
  induction rules with
  | nil => simp at witness
  | cons first rest ih =>
    obtain ⟨rule, member, covers⟩ := witness
    rcases List.mem_cons.mp member with same | later
    · subst rule
      exact Or.inl ⟨allowed first (by simp), covers⟩
    · exact Or.inr ⟨Or.inl (allowed first (by simp)),
        ih (fun item member => allowed item (List.mem_cons_of_mem _ member)) ⟨rule, later, covers⟩⟩

lemma safe_prefix_preserves_permit (mask : AclFlowSelector) (earlierRules rest : List Rule)
    (safe : ∀ rule ∈ earlierRules, rule.verdict = .allow ∨ ∃ atom ∈ rule.atoms, mask.Rejects atom)
    (permit : mask.IsPermittedByAclChain rest) : mask.IsPermittedByAclChain (earlierRules ++ rest) := by
  induction earlierRules with
  | nil => exact permit
  | cons first restPrefix ih =>
    exact Or.inr ⟨safe first (by simp),
      ih (fun item member => safe item (List.mem_cons_of_mem _ member))⟩

def checkAclPermit (index : AclRuleIndex) (mask : AclFlowSelector) (witness : AclPermitWitness) : Bool :=
  checkAclPrefix mask index.earlierRules witness.rejectedAtoms &&
    match index.allowed.lookup witness.ruleIndex with
    | none => false
    | some rule => decide (∀ atom ∈ rule.atoms, mask.Allows atom)

theorem table_driven_acl_certificate_sound (index : AclRuleIndex) (valid : index.Valid)
    (mask : AclFlowSelector) (witness : AclPermitWitness)
    (checked : checkAclPermit index mask witness = true) : mask.IsPermittedByAclChain index.rules := by
  have parts := Bool.and_eq_true_iff.mp checked
  apply safe_prefix_preserves_permit _ _ _ (checked_acl_prefix_is_safe _ _ _ parts.1)
  apply allow_only_rules_permit _ _ valid
  cases found : index.allowed.lookup witness.ruleIndex with
  | none => simp [found] at parts
  | some rule =>
    exact ⟨rule, index.allowed.lookup_mem _ _ found, of_decide_eq_true (by simpa [found] using parts.2)⟩

end TDN.PacketPolicy
