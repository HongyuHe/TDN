import TDN.Models.PayloadByteOriginPath
import TDN.Models.ByteFlowsWithKernelReplies
import TDN.Models.PlaintextReassemblyPreservesEnclave
import TDN.Models.SingleEnclaveDeviceReplies
import TDN.Models.TunnelEncryptionEvents

namespace TDN.ByteProtectionEvents
open DataPlaneForwarding

def encapLayerIds : KernelResponses.State DataPlaneForwarding.State → List Nat
  | .network state | .generated state _ _ | .routed state _ _ _ => state.frame.encapLayerIds
  | .consumed => []

def system (c : DataPlaneForwarding.DataPlaneModel) (strict uniformOwners : List Nat) :=
  ByteLineage.lts
    (KernelResponses.lts (DataPlaneForwarding.lts c) (UniformDomainResponses.responseConfig c strict uniformOwners))
    (ResponseByteFlows.assembly PlaintextAssembly)

def EncryptionEvent (c : DataPlaneForwarding.DataPlaneModel) (tag : Nat)
    (left : KernelResponses.State DataPlaneForwarding.State)
    (action : Option (KernelResponses.Action DataPlaneForwarding.Action))
    (right : KernelResponses.State DataPlaneForwarding.State) : Prop :=
  ∃ before after, left = .network before ∧ right = .network after ∧
    action = some (.network .encrypt) ∧ Step c before .encrypt after ∧
    after.frame.encapLayerIds = tag :: before.frame.encapLayerIds

lemma added_tag_is_actual_encryption (c : DataPlaneForwarding.DataPlaneModel) (strict uniformOwners : List Nat)
    {before after : KernelResponses.State DataPlaneForwarding.State}
    {action : Option (KernelResponses.Action DataPlaneForwarding.Action)} {tag : Nat}
    (step : (system c strict uniformOwners).Tr before action after)
    (absent : tag ∉ encapLayerIds before) (present : tag ∈ encapLayerIds after) :
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
    | consume => simp [encapLayerIds] at present
  | assemble compatible =>
    cases before <;> cases after <;>
      simp only [ResponseByteFlows.assembly] at compatible <;> try contradiction
    simp only [encapLayerIds, compatible.2.2.2.2, List.not_mem_nil] at present

theorem trace_tag_addition_has_encryption (c : DataPlaneForwarding.DataPlaneModel) (strict uniformOwners : List Nat)
    (tag : Nat) {before after : KernelResponses.State DataPlaneForwarding.State}
    {actions : List (Option (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (system c strict uniformOwners).MTr before actions after)
    (absent : tag ∉ encapLayerIds before) (present : tag ∈ encapLayerIds after) :
    TraceEvents.Contains (system c strict uniformOwners) before actions after
      (EncryptionEvent c tag) := by
  have event := TraceEvents.changing_predicate_has_event
    (system c strict uniformOwners) (fun state => tag ∉ encapLayerIds state) run absent (fun no => no present)
  apply TraceEvents.map_event _ event
  intro left action right step changed
  exact added_tag_is_actual_encryption c strict uniformOwners step changed.1
    (Classical.not_not.mp changed.2)

lemma domain_lineage_preservation (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat)
    (allowed : Nat → Prop) (strict uniformOwners : List Nat)
    (conditions : LocalDomainConditions c expectedEncapStack allowed)
    (guards : ∀ iface, c.owner iface ∈ strict →
      c.outputFallback iface = .deny ∧ ∀ rule ∈ c.outputRules iface,
        rule.verdict = .allow → KernelResponses.SafeResponseRule rule)
    (uniform : ∀ owner ∈ uniformOwners, UniformDomainResponses.Uniform c expectedEncapStack allowed owner) :
    (system c strict uniformOwners).TrInv
      (KernelResponses.ProvenanceInvariant (UniformDomainResponses.responseConfig c strict uniformOwners)
        (DomainInvariant c expectedEncapStack allowed)) := by
  apply ByteLineage.local_checks_preserve_lineage
  · exact KernelResponses.local_reply_checks_preserve_network_safety
      (DataPlaneForwarding.lts c) (UniformDomainResponses.responseConfig c strict uniformOwners)
      (DomainInvariant c expectedEncapStack allowed)
      (fun _ _ _ step safe => step_preserves_domain_invariant conditions step safe)
      (UniformDomainResponses.reply_preserves_domain c expectedEncapStack allowed strict uniformOwners
        conditions guards uniform)
  · intro before after compatible safe
    cases before <;> cases after <;>
      simp only [ResponseByteFlows.assembly] at compatible <;> try contradiction
    exact plaintext_assembly_preserves_domain c expectedEncapStack allowed compatible safe

end TDN.ByteProtectionEvents
