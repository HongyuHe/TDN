import TDN.Semantics.ByteLineage
import TDN.Semantics.ResponseByteFlows
import TDN.Semantics.PlaintextAssembly
import TDN.Semantics.UniformDomainResponses
import TDN.Semantics.ExecutionEvents

namespace TDN.ByteProtectionEvents
open Execution

def tags : KernelResponses.State Execution.State → List Nat
  | .network state | .generated state _ _ | .routed state _ _ _ => state.frame.tags
  | .consumed => []

def system (c : Execution.Config) (strict uniformOwners : List Nat) :=
  ByteLineage.lts
    (KernelResponses.lts (Execution.lts c) (UniformDomainResponses.responseConfig c strict uniformOwners))
    (ResponseByteFlows.assembly PlaintextAssembly)

def EncryptionEvent (c : Execution.Config) (tag : Nat)
    (left : KernelResponses.State Execution.State)
    (action : Option (KernelResponses.Action Execution.Action))
    (right : KernelResponses.State Execution.State) : Prop :=
  ∃ before after, left = .network before ∧ right = .network after ∧
    action = some (.network .encrypt) ∧ Step c before .encrypt after ∧
    after.frame.tags = tag :: before.frame.tags

lemma added_tag_is_actual_encryption (c : Execution.Config) (strict uniformOwners : List Nat)
    {before after : KernelResponses.State Execution.State}
    {action : Option (KernelResponses.Action Execution.Action)} {tag : Nat}
    (step : (system c strict uniformOwners).Tr before action after)
    (absent : tag ∉ tags before) (present : tag ∈ tags after) :
    EncryptionEvent c tag before action after := by
  cases step with
  | network operation =>
    cases operation with
    | network step =>
      obtain ⟨label, added⟩ := missing_tag_added_only_by_encryption step absent present
      cases label
      exact ⟨_, _, rfl, rfl, rfl, step, added⟩
    | generate => exact False.elim (absent present)
    | route => exact False.elim (absent present)
    | emit => exact False.elim (absent present)
    | consume => simp [tags] at present
  | assemble compatible =>
    cases before <;> cases after <;>
      simp only [ResponseByteFlows.assembly] at compatible <;> try contradiction
    simp only [tags, compatible.2.2.2.2, List.not_mem_nil] at present

theorem trace_tag_addition_has_encryption (c : Execution.Config) (strict uniformOwners : List Nat)
    (tag : Nat) {before after : KernelResponses.State Execution.State}
    {actions : List (Option (KernelResponses.Action Execution.Action))}
    (run : (system c strict uniformOwners).MTr before actions after)
    (absent : tag ∉ tags before) (present : tag ∈ tags after) :
    TraceEvents.Contains (system c strict uniformOwners) before actions after
      (EncryptionEvent c tag) := by
  have event := TraceEvents.changing_predicate_has_event
    (system c strict uniformOwners) (fun state => tag ∉ tags state) run absent (fun no => no present)
  apply TraceEvents.map_event _ event
  intro left action right step changed
  exact added_tag_is_actual_encryption c strict uniformOwners step changed.1
    (Classical.not_not.mp changed.2)

lemma domain_lineage_preservation (c : Execution.Config) (layout : Nat → List Nat)
    (allowed : Nat → Prop) (strict uniformOwners : List Nat)
    (conditions : LocalDomainConditions c layout allowed)
    (guards : ∀ port, c.owner port ∈ strict →
      c.outputFallback port = .deny ∧ ∀ rule ∈ c.outputRules port,
        rule.verdict = .allow → KernelResponses.SafeResponseRule rule)
    (uniform : ∀ owner ∈ uniformOwners, UniformDomainResponses.Uniform c layout allowed owner) :
    (system c strict uniformOwners).TrInv
      (KernelResponses.ProvenanceInvariant (UniformDomainResponses.responseConfig c strict uniformOwners)
        (DomainInvariant c layout allowed)) := by
  apply ByteLineage.local_checks_preserve_lineage
  · exact KernelResponses.local_reply_checks_preserve_network_safety
      (Execution.lts c) (UniformDomainResponses.responseConfig c strict uniformOwners)
      (DomainInvariant c layout allowed)
      (fun _ _ _ step safe => step_preserves_domain_invariant conditions step safe)
      (UniformDomainResponses.reply_preserves_domain c layout allowed strict uniformOwners
        conditions guards uniform)
  · intro before after compatible safe
    cases before <;> cases after <;>
      simp only [ResponseByteFlows.assembly] at compatible <;> try contradiction
    exact plaintext_assembly_preserves_domain c layout allowed compatible safe

end TDN.ByteProtectionEvents
