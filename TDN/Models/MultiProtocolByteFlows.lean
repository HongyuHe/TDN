import TDN.Models.PayloadByteOriginPath
import TDN.Models.MultiProtocolEncryptionEvents

namespace TDN.MultiProtocolForwarding
open LayeredFrame

def PlainByteAssembly (before after : TunnelForwardingState) : Prop :=
  before.datapathStage = .received ∧ after.datapathStage = .received ∧ before.iface = after.iface ∧
  before.frame.body.protectionLayers = [] ∧
  ((∃ header, after.frame.body = .datagram header) ∨
   (∃ header, after.frame.body = .ethernet header))

lemma plain_byte_assembly_preserves_stack (c : TunnelForwardingModel) (expectedEncapStack : Nat → List Nat)
    {before after : TunnelForwardingState} (assembly : PlainByteAssembly before after)
    (safe : EncapStackConsistent c expectedEncapStack before) : EncapStackConsistent c expectedEncapStack after := by
  obtain ⟨beforePhase, afterPhase, iface, empty, body⟩ := assembly
  have beforeStack : before.frame.body.protectionLayers = expectedEncapStack before.iface := by
    simpa only [beforePhase] using safe.2
  have afterStack : expectedEncapStack after.iface = [] := iface ▸ (beforeStack.symm.trans empty)
  rcases body with ⟨header, plain⟩ | ⟨header, plain⟩ <;>
    simp [EncapStackConsistent, CarrierBodies, afterPhase, plain, Body.protectionLayers, afterStack]

def byteSystem {Byte : Type} (c : TunnelForwardingModel) (origin : TunnelForwardingState → Byte → Prop) :=
  ByteFlows.lts (lts c) origin PlainByteAssembly

theorem mixed_byte_forwarding_preserves_stack {Byte : Type}
    (c : TunnelForwardingModel) (expectedEncapStack : Nat → List Nat) (origin : TunnelForwardingState → Byte → Prop)
    (conditions : LocalConditions c expectedEncapStack)
    (source : ∀ state byte, origin state byte → EncapStackConsistent c expectedEncapStack state)
    {after : List (ByteFlows.PacketBytes TunnelForwardingState Byte)} {actions : List (ByteFlows.ByteFlowAction TunnelForwardingAction)}
    (run : (byteSystem c origin).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent c expectedEncapStack) after := by
  exact ByteFlows.all_traces_preserve_byte_properties (lts c) origin PlainByteAssembly
    (fun _ => EncapStackConsistent c expectedEncapStack) source
    (fun _ _ _ _ step safe => step_preserves_stack conditions step safe)
    (fun before after _ compatible safe =>
      plain_byte_assembly_preserves_stack c expectedEncapStack compatible safe)
    run (by simp [ByteFlows.Safe])

def payloadByteOriginPath (c : TunnelForwardingModel) := PayloadByteOriginPath.lts (lts c) PlainByteAssembly

lemma byte_lineage_preserves_stack (c : TunnelForwardingModel) (expectedEncapStack : Nat → List Nat)
    (conditions : LocalConditions c expectedEncapStack) :
    (payloadByteOriginPath c).TrInv (EncapStackConsistent c expectedEncapStack) :=
  PayloadByteOriginPath.local_checks_preserve_lineage (lts c) PlainByteAssembly (EncapStackConsistent c expectedEncapStack)
    (fun _ _ _ step safe => step_preserves_stack conditions step safe)
    (fun _ _ compatible safe => plain_byte_assembly_preserves_stack c expectedEncapStack compatible safe)

def ByteEncryptionEvent (c : TunnelForwardingModel) (tag : Nat)
    (before : TunnelForwardingState) (action : Option TunnelForwardingAction) (after : TunnelForwardingState) : Prop :=
  ∃ label, action = some label ∧ TunnelForwardingStep c before label after ∧ IsEncryption label ∧
    after.frame.body.protectionLayers = tag :: before.frame.body.protectionLayers

lemma byte_layer_added_only_by_encryption (c : TunnelForwardingModel)
    {before after : TunnelForwardingState} {action : Option TunnelForwardingAction} {tag : Nat}
    (step : (payloadByteOriginPath c).Tr before action after)
    (absent : tag ∉ before.frame.body.protectionLayers)
    (present : tag ∈ after.frame.body.protectionLayers) :
    ByteEncryptionEvent c tag before action after := by
  cases step with
  | network step =>
    obtain ⟨encryption, added⟩ := missing_layer_requires_encryption step absent present
    exact ⟨_, rfl, step, encryption, added⟩
  | assemble compatible =>
    rcases compatible.2.2.2.2 with ⟨header, plain⟩ | ⟨header, plain⟩ <;>
      simp [plain, Body.protectionLayers] at present

theorem byte_path_layer_addition_has_encryption (c : TunnelForwardingModel) (tag : Nat)
    {before after : TunnelForwardingState} {actions : List (Option TunnelForwardingAction)}
    (run : (payloadByteOriginPath c).MTr before actions after)
    (absent : tag ∉ before.frame.body.protectionLayers)
    (present : tag ∈ after.frame.body.protectionLayers) :
    TraceEvents.Contains (payloadByteOriginPath c) before actions after (ByteEncryptionEvent c tag) := by
  have event := TraceEvents.changing_predicate_has_event (payloadByteOriginPath c)
    (fun state => tag ∉ state.frame.body.protectionLayers) run absent (fun no => no present)
  apply TraceEvents.map_event _ event
  intro left action right step changed
  exact byte_layer_added_only_by_encryption c step changed.1 (Classical.not_not.mp changed.2)

def ByteOrderedEncryptions (c : TunnelForwardingModel) (inner outer : Nat)
    (before : TunnelForwardingState) (actions : List (Option TunnelForwardingAction)) (after : TunnelForwardingState) : Prop :=
  ∃ earlier later left action right,
    actions = earlier ++ action :: later ∧
    (payloadByteOriginPath c).MTr before earlier left ∧ (payloadByteOriginPath c).Tr left action right ∧
    (payloadByteOriginPath c).MTr right later after ∧ ByteEncryptionEvent c outer left action right ∧
    TraceEvents.Contains (payloadByteOriginPath c) before earlier left (ByteEncryptionEvent c inner)

theorem mixed_byte_path_requires_ordered_encryptions (c : TunnelForwardingModel) (expectedEncapStack : Nat → List Nat)
    (conditions : LocalConditions c expectedEncapStack) (inner outer : Nat)
    (placement : ∀ iface, (expectedEncapStack iface).head? = some outer → expectedEncapStack iface = [outer, inner])
    {before after : TunnelForwardingState} {actions : List (Option TunnelForwardingAction)}
    (run : (payloadByteOriginPath c).MTr before actions after)
    (initial : EncapStackConsistent c expectedEncapStack before)
    (empty : before.frame.body.protectionLayers = [])
    (present : outer ∈ after.frame.body.protectionLayers) :
    ByteOrderedEncryptions c inner outer before actions after := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, outerEvent⟩ :=
    byte_path_layer_addition_has_encryption c outer run (by simp [empty]) present
  obtain ⟨label, actionEq, operation, encryption, added⟩ := outerEvent
  have preserved := Cslib.LTS.mtrInv_of_trInv
    (byte_lineage_preserves_stack c expectedEncapStack conditions) before _ right
    (first.stepR (payloadByteOriginPath c) step) initial
  have stack := encryption_output_layout operation encryption preserved
  have head : (expectedEncapStack right.iface).head? = some outer := by
    rw [← stack, added]
    rfl
  have innerStack : left.frame.body.protectionLayers = [inner] :=
    (List.cons.inj (added.symm.trans (stack.trans (placement right.iface head)))).2
  exact ⟨earlier, later, left, action, right, sequence, first, step, last,
    ⟨label, actionEq, operation, encryption, added⟩,
    byte_path_layer_addition_has_encryption c inner first (by simp [empty])
      (by simp [innerStack])⟩

end TDN.MultiProtocolForwarding
