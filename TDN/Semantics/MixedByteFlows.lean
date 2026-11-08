import TDN.Semantics.ByteLineage
import TDN.Semantics.MultiProtocolEvents

namespace TDN.MultiProtocolExecution
open LayeredFrame

def PlainByteAssembly (before after : State) : Prop :=
  before.datapathStage = .received ∧ after.datapathStage = .received ∧ before.iface = after.iface ∧
  before.frame.body.protectionLayers = [] ∧
  ((∃ header, after.frame.body = .datagram header) ∨
   (∃ header, after.frame.body = .ethernet header))

lemma plain_byte_assembly_preserves_stack (c : Config) (expectedEncapStack : Nat → List Nat)
    {before after : State} (assembly : PlainByteAssembly before after)
    (safe : StackInvariant c expectedEncapStack before) : StackInvariant c expectedEncapStack after := by
  obtain ⟨beforePhase, afterPhase, iface, empty, body⟩ := assembly
  have beforeStack : before.frame.body.protectionLayers = expectedEncapStack before.iface := by
    simpa only [beforePhase] using safe.2
  have afterStack : expectedEncapStack after.iface = [] := iface ▸ (beforeStack.symm.trans empty)
  rcases body with ⟨header, plain⟩ | ⟨header, plain⟩ <;>
    simp [StackInvariant, CarrierBodies, afterPhase, plain, Body.protectionLayers, afterStack]

def byteSystem {Byte : Type} (c : Config) (origin : State → Byte → Prop) :=
  ByteFlows.lts (lts c) origin PlainByteAssembly

theorem mixed_byte_execution_preserves_stack {Byte : Type}
    (c : Config) (expectedEncapStack : Nat → List Nat) (origin : State → Byte → Prop)
    (conditions : LocalConditions c expectedEncapStack)
    (source : ∀ state byte, origin state byte → StackInvariant c expectedEncapStack state)
    {after : List (ByteFlows.Carrier State Byte)} {actions : List (ByteFlows.Action Action)}
    (run : (byteSystem c origin).MTr [] actions after) :
    ByteFlows.Safe (fun _ => StackInvariant c expectedEncapStack) after := by
  exact ByteFlows.all_executions_preserve_byte_properties (lts c) origin PlainByteAssembly
    (fun _ => StackInvariant c expectedEncapStack) source
    (fun _ _ _ _ step safe => step_preserves_stack conditions step safe)
    (fun before after _ compatible safe =>
      plain_byte_assembly_preserves_stack c expectedEncapStack compatible safe)
    run (by simp [ByteFlows.Safe])

def byteLineage (c : Config) := ByteLineage.lts (lts c) PlainByteAssembly

lemma byte_lineage_preserves_stack (c : Config) (expectedEncapStack : Nat → List Nat)
    (conditions : LocalConditions c expectedEncapStack) :
    (byteLineage c).TrInv (StackInvariant c expectedEncapStack) :=
  ByteLineage.local_checks_preserve_lineage (lts c) PlainByteAssembly (StackInvariant c expectedEncapStack)
    (fun _ _ _ step safe => step_preserves_stack conditions step safe)
    (fun _ _ compatible safe => plain_byte_assembly_preserves_stack c expectedEncapStack compatible safe)

def ByteEncryptionEvent (c : Config) (tag : Nat)
    (before : State) (action : Option Action) (after : State) : Prop :=
  ∃ label, action = some label ∧ Step c before label after ∧ IsEncryption label ∧
    after.frame.body.protectionLayers = tag :: before.frame.body.protectionLayers

lemma byte_layer_added_only_by_encryption (c : Config)
    {before after : State} {action : Option Action} {tag : Nat}
    (step : (byteLineage c).Tr before action after)
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

theorem byte_path_layer_addition_has_encryption (c : Config) (tag : Nat)
    {before after : State} {actions : List (Option Action)}
    (run : (byteLineage c).MTr before actions after)
    (absent : tag ∉ before.frame.body.protectionLayers)
    (present : tag ∈ after.frame.body.protectionLayers) :
    TraceEvents.Contains (byteLineage c) before actions after (ByteEncryptionEvent c tag) := by
  have event := TraceEvents.changing_predicate_has_event (byteLineage c)
    (fun state => tag ∉ state.frame.body.protectionLayers) run absent (fun no => no present)
  apply TraceEvents.map_event _ event
  intro left action right step changed
  exact byte_layer_added_only_by_encryption c step changed.1 (Classical.not_not.mp changed.2)

def ByteOrderedEncryptions (c : Config) (inner outer : Nat)
    (before : State) (actions : List (Option Action)) (after : State) : Prop :=
  ∃ earlier later left action right,
    actions = earlier ++ action :: later ∧
    (byteLineage c).MTr before earlier left ∧ (byteLineage c).Tr left action right ∧
    (byteLineage c).MTr right later after ∧ ByteEncryptionEvent c outer left action right ∧
    TraceEvents.Contains (byteLineage c) before earlier left (ByteEncryptionEvent c inner)

theorem mixed_byte_path_requires_ordered_encryptions (c : Config) (expectedEncapStack : Nat → List Nat)
    (conditions : LocalConditions c expectedEncapStack) (inner outer : Nat)
    (placement : ∀ iface, (expectedEncapStack iface).head? = some outer → expectedEncapStack iface = [outer, inner])
    {before after : State} {actions : List (Option Action)}
    (run : (byteLineage c).MTr before actions after)
    (initial : StackInvariant c expectedEncapStack before)
    (empty : before.frame.body.protectionLayers = [])
    (present : outer ∈ after.frame.body.protectionLayers) :
    ByteOrderedEncryptions c inner outer before actions after := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, outerEvent⟩ :=
    byte_path_layer_addition_has_encryption c outer run (by simp [empty]) present
  obtain ⟨label, actionEq, operation, encryption, added⟩ := outerEvent
  have preserved := Cslib.LTS.mtrInv_of_trInv
    (byte_lineage_preserves_stack c expectedEncapStack conditions) before _ right
    (first.stepR (byteLineage c) step) initial
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

end TDN.MultiProtocolExecution
