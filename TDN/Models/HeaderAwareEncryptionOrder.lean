import TDN.Models.HeaderAwareEncapPreservation
import TDN.Models.MultiProtocolEncryptionEvents

namespace TDN.MultiProtocolForwarding
open LayeredFrame

lemma headered_encryption_output_layout {c : Config} {expectedEncapStack : Nat → List Nat}
    {before after : State} {action : Action}
    (step : Step c before action after) (label : IsEncryption action)
    (invariant : HeaderedStackInvariant c expectedEncapStack after) :
    after.frame.body.protectionLayers = expectedEncapStack after.iface := by
  cases step <;> simp only [IsEncryption, reduceCtorEq, false_or] at label
  case encryptIPsec => exact invariant.2.2.1
  case encryptMACsec iface association configured datapathStage logical emits =>
    simpa only [HeaderedStackInvariant, datapathStage] using invariant.2.2

theorem headered_nested_stack_requires_ordered_encryptions
    (c : Config) (expectedEncapStack : Nat → List Nat)
    (conditions : HeaderedLocalConditions c expectedEncapStack)
    (processing : HeaderProcessing) (mode : c.headerProcessing = some processing)
    (bounds : HeaderBounds processing) (innerTag outerTag : Nat)
    (placement : ∀ iface, (expectedEncapStack iface).head? = some outerTag →
      expectedEncapStack iface = [outerTag, innerTag])
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after)
    (initial : HeaderedStackInvariant c expectedEncapStack before)
    (empty : before.frame.body.protectionLayers = [])
    (present : outerTag ∈ after.frame.body.protectionLayers) :
    OrderedEncryptions c innerTag outerTag before actions after := by
  have absent : outerTag ∉ before.frame.body.protectionLayers := by simp [empty]
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, label, added, payload⟩ :=
    boundary_addition_has_actual_encryption c outerTag run absent present
  have preserved := headered_traces_preserve_stack c expectedEncapStack conditions processing mode bounds
    (first.stepR (lts c) step) initial
  have output := headered_encryption_output_layout step label preserved
  have head : (expectedEncapStack right.iface).head? = some outerTag := by
    rw [← output, added]
    rfl
  have shape : outerTag :: left.frame.body.protectionLayers = [outerTag, innerTag] :=
    added.symm.trans (output.trans (placement right.iface head))
  have inner := (List.cons.inj shape).2
  have innerPresent : innerTag ∈ left.frame.body.protectionLayers := by simp [inner]
  have innerAbsent : innerTag ∉ before.frame.body.protectionLayers := by simp [empty]
  exact ⟨earlier, later, left, action, right, sequence, first, step, last, label, added, payload,
    boundary_addition_has_actual_encryption c innerTag first innerAbsent innerPresent⟩

end TDN.MultiProtocolForwarding
