import TDN.Models.MultiProtocolEncapPreservation
import TDN.Models.LocateTransitionStepInTrace

namespace TDN.MultiProtocolForwarding
open LayeredFrame

lemma unwrap_preserves_original_ethernet
    (localAddress remote sourcePort destinationPort localSession : Nat) {protocol networkProtocol : String} (before after : Body)
    (unwrapped : unwrapCarrier localAddress remote sourcePort destinationPort localSession before protocol networkProtocol = some after) :
    after.originalEthernet = before.originalEthernet := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    next matched => cases unwrapped; rfl
    next missed => cases unwrapped

lemma step_preserves_original_ethernet {c : Config} {before after : State} {action : Action}
    (step : Step c before action after) :
    after.frame.body.originalEthernet = before.frame.body.originalEthernet := by
  cases step <;> simp only [Config.forwardedFrame_body, Config.ipsecFrame_body,
    Config.macsecFrame_body, Config.macsec_pdu_frame_body, Config.carrierFrame_body, Config.restoredFrame_body] <;> try rfl
  all_goals try simp_all only [Body.originalEthernet]
  all_goals exact unwrap_preserves_original_ethernet _ _ _ _ _ _ _ ‹_›

theorem all_traces_preserve_original_ethernet (c : Config)
    {before after : State} {actions : List Action} (run : (lts c).MTr before actions after) :
    after.frame.body.originalEthernet = before.frame.body.originalEthernet := by
  have preserved : (lts c).TrInv
      (fun state => state.frame.body.originalEthernet = before.frame.body.originalEthernet) := by
    intro first action last step valid
    exact (step_preserves_original_ethernet step).trans valid
  exact Cslib.LTS.mtrInv_of_trInv preserved before actions after run rfl

def IsEncryption (action : Action) : Prop :=
  action = .encryptIPsec ∨ action = .encryptMACsec

def IsDecryption (action : Action) : Prop :=
  action = .decryptIPsec ∨ action = .decryptMACsec

lemma step_layer_effect {c : Config} {before after : State} {action : Action}
    (step : Step c before action after) :
    after.frame.body.protectionLayers = before.frame.body.protectionLayers ∨
    (IsEncryption action ∧ ∃ tag,
      after.frame.body.protectionLayers = tag :: before.frame.body.protectionLayers) ∨
    (IsDecryption action ∧ ∃ tag,
      before.frame.body.protectionLayers = tag :: after.frame.body.protectionLayers) := by
  cases step <;> simp only [Config.forwardedFrame_body, Config.ipsecFrame_body,
    Config.macsecFrame_body, Config.macsec_pdu_frame_body, Config.carrierFrame_body, Config.restoredFrame_body] <;> try exact Or.inl rfl
  all_goals first
    | exact Or.inl (successful_carrier_unwrap_preserves_layers _ _ _ _ _ _ _ ‹_›)
    | simp_all [IsEncryption, IsDecryption, Body.protectionLayers]

lemma missing_layer_requires_encryption {c : Config} {before after : State} {action : Action}
    {tag : Nat} (step : Step c before action after)
    (absent : tag ∉ before.frame.body.protectionLayers)
    (present : tag ∈ after.frame.body.protectionLayers) :
    IsEncryption action ∧
      after.frame.body.protectionLayers = tag :: before.frame.body.protectionLayers := by
  rcases step_layer_effect step with same | ⟨label, newTag, added⟩ | ⟨label, oldTag, removed⟩
  · exact False.elim (absent (same ▸ present))
  · rw [added] at present
    rcases List.mem_cons.mp present with equal | previous
    · exact ⟨label, by simpa [equal] using added⟩
    · exact False.elim (absent previous)
  · exact False.elim (absent (removed ▸ List.mem_cons_of_mem oldTag present))

lemma removed_layer_requires_decryption {c : Config} {before after : State} {action : Action}
    {tag : Nat} (step : Step c before action after)
    (present : tag ∈ before.frame.body.protectionLayers)
    (absent : tag ∉ after.frame.body.protectionLayers) :
    IsDecryption action ∧
      before.frame.body.protectionLayers = tag :: after.frame.body.protectionLayers := by
  rcases step_layer_effect step with same | ⟨label, newTag, added⟩ | ⟨label, oldTag, removed⟩
  · exact False.elim (absent (same.symm ▸ present))
  · exact False.elim (absent (added ▸ List.mem_cons_of_mem newTag present))
  · rw [removed] at present
    rcases List.mem_cons.mp present with equal | previous
    · exact ⟨label, by simpa [equal] using removed⟩
    · exact False.elim (absent previous)

theorem boundary_addition_has_actual_encryption (c : Config) (tag : Nat)
    {before after : State} {actions : List Action} (run : (lts c).MTr before actions after)
    (initial : tag ∉ before.frame.body.protectionLayers)
    (final : tag ∈ after.frame.body.protectionLayers) :
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => IsEncryption action ∧
        right.frame.body.protectionLayers = tag :: left.frame.body.protectionLayers ∧
        left.frame.payload = before.frame.payload) := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, absent, present⟩ :=
    TraceEvents.changing_predicate_has_event (lts c)
      (fun state => tag ∉ state.frame.body.protectionLayers) run initial (fun h => h final)
  obtain ⟨label, added⟩ := missing_layer_requires_encryption step absent (Classical.not_not.mp present)
  exact ⟨earlier, later, left, action, right, sequence, first, step, last,
    label, added, (all_traces_preserve_payload c first).1⟩

theorem boundary_removal_has_actual_decryption (c : Config) (tag : Nat)
    {before after : State} {actions : List Action} (run : (lts c).MTr before actions after)
    (initial : tag ∈ before.frame.body.protectionLayers)
    (final : tag ∉ after.frame.body.protectionLayers) :
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => IsDecryption action ∧
        left.frame.body.protectionLayers = tag :: right.frame.body.protectionLayers ∧
        left.frame.payload = before.frame.payload) := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, present, absent⟩ :=
    TraceEvents.changing_predicate_has_event (lts c)
      (fun state => tag ∈ state.frame.body.protectionLayers) run initial final
  obtain ⟨label, removed⟩ := removed_layer_requires_decryption step present absent
  exact ⟨earlier, later, left, action, right, sequence, first, step, last,
    label, removed, (all_traces_preserve_payload c first).1⟩

lemma encryption_output_layout {c : Config} {expectedEncapStack : Nat → List Nat}
    {before after : State} {action : Action}
    (step : Step c before action after) (label : IsEncryption action)
    (invariant : EncapStackConsistent c expectedEncapStack after) :
    after.frame.body.protectionLayers = expectedEncapStack after.iface := by
  cases step <;> simp only [IsEncryption, reduceCtorEq, false_or] at label
  case encryptIPsec => exact invariant.2.1
  case encryptMACsec iface association configured datapathStage logical emits =>
    simpa only [EncapStackConsistent, datapathStage] using invariant.2

def OrderedEncryptions (c : Config) (innerTag outerTag : Nat)
    (before : State) (actions : List Action) (after : State) : Prop :=
  ∃ earlier later left action right,
    actions = earlier ++ action :: later ∧
    (lts c).MTr before earlier left ∧ Step c left action right ∧
    (lts c).MTr right later after ∧
    IsEncryption action ∧
    right.frame.body.protectionLayers = outerTag :: left.frame.body.protectionLayers ∧
    left.frame.payload = before.frame.payload ∧
    TraceEvents.Contains (lts c) before earlier left
      (fun a label b => IsEncryption label ∧
        b.frame.body.protectionLayers = innerTag :: a.frame.body.protectionLayers ∧
        a.frame.payload = before.frame.payload)

theorem nested_stack_requires_ordered_encryptions (c : Config) (expectedEncapStack : Nat → List Nat)
    (conditions : LocalConditions c expectedEncapStack) (innerTag outerTag : Nat)
    (placement : ∀ iface, (expectedEncapStack iface).head? = some outerTag →
      expectedEncapStack iface = [outerTag, innerTag])
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after) (initial : EncapStackConsistent c expectedEncapStack before)
    (empty : before.frame.body.protectionLayers = [])
    (present : outerTag ∈ after.frame.body.protectionLayers) :
    OrderedEncryptions c innerTag outerTag before actions after := by
  have absent : outerTag ∉ before.frame.body.protectionLayers := by simp [empty]
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, label, added, payload⟩ :=
    boundary_addition_has_actual_encryption c outerTag run absent present
  have preserved := all_traces_preserve_stack c expectedEncapStack conditions
    (first.stepR (lts c) step) initial
  have output := encryption_output_layout step label preserved
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
