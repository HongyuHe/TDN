import TDN.Models.EncapStackPreservation
import TDN.Models.LocateTransitionStepInTrace

namespace TDN.DataPlaneForwarding

lemma missing_tag_added_only_by_encryption {c : DataPlaneModel} {before after : State}
    {action : Action} {tag : Nat} (step : Step c before action after)
    (absent : tag ∉ before.frame.encapLayerIds) (present : tag ∈ after.frame.encapLayerIds) :
    action = .encrypt ∧ after.frame.encapLayerIds = tag :: before.frame.encapLayerIds := by
  cases step <;> try exact False.elim (absent present)
  case encrypt association sa selected installed bound =>
    change tag ∈ association.tag :: _ at present
    rcases List.mem_cons.mp present with head | tail
    · exact ⟨rfl, by rw [head]; rfl⟩
    · exact False.elim (absent tail)
  case decrypt association sa header rest tracking configured installed bound received outerSource outerDestination esp selected =>
    apply False.elim
    apply absent
    simp only [Frame.encapLayerIds, received, List.map_cons]
    exact List.mem_cons_of_mem _ present

lemma present_tag_removed_only_by_decryption {c : DataPlaneModel} {before after : State}
    {action : Action} {tag : Nat} (step : Step c before action after)
    (present : tag ∈ before.frame.encapLayerIds) (absent : tag ∉ after.frame.encapLayerIds) :
    action = .decrypt ∧ before.frame.encapLayerIds = tag :: after.frame.encapLayerIds := by
  cases step <;> try exact False.elim (absent present)
  case encrypt association sa selected installed bound =>
    exact False.elim (absent (List.mem_cons_of_mem _ present))
  case decrypt association sa header rest tracking configured installed bound received outerSource outerDestination esp selected =>
    simp only [Frame.encapLayerIds, received, List.map_cons] at present
    rcases List.mem_cons.mp present with head | tail
    · refine ⟨rfl, ?_⟩
      simp only [Frame.encapLayerIds, received, List.map_cons]
      rw [head]
    · exact False.elim (absent tail)

lemma forwarding_payload_identity (c : DataPlaneModel) {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after) : after.frame.payload = before.frame.payload := by
  induction run with
  | refl => rfl
  | stepL step rest ih =>
    have same : _ := ih
    cases step <;> exact same

theorem boundary_layer_removal_has_decryption (c : DataPlaneModel) (tag : Nat)
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after)
    (initial : tag ∈ before.frame.encapLayerIds) (final : tag ∉ after.frame.encapLayerIds) :
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => action = .decrypt ∧
        left.frame.encapLayerIds = tag :: right.frame.encapLayerIds ∧ left.frame.payload = before.frame.payload) := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, present, absent⟩ :=
    TraceEvents.changing_predicate_has_event (lts c) (fun state => tag ∈ state.frame.encapLayerIds)
      run initial final
  obtain ⟨label, removed⟩ := present_tag_removed_only_by_decryption step present absent
  exact ⟨earlier, later, left, action, right, sequence, first, step, last,
    label, removed, forwarding_payload_identity c first⟩

theorem boundary_layer_addition_has_encryption (c : DataPlaneModel) (tag : Nat)
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after)
    (initial : tag ∉ before.frame.encapLayerIds) (final : tag ∈ after.frame.encapLayerIds) :
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => action = .encrypt ∧
        right.frame.encapLayerIds = tag :: left.frame.encapLayerIds ∧ left.frame.payload = before.frame.payload) := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, absent, present⟩ :=
    TraceEvents.changing_predicate_has_event (lts c) (fun state => tag ∉ state.frame.encapLayerIds)
      run initial (fun h => h final)
  have member : tag ∈ right.frame.encapLayerIds := Classical.not_not.mp present
  obtain ⟨label, added⟩ := missing_tag_added_only_by_encryption step absent member
  exact ⟨earlier, later, left, action, right, sequence, first, step, last,
    label, added, forwarding_payload_identity c first⟩

lemma outer_encryption_has_inner_stack {c : DataPlaneModel} {expectedEncapStack : Nat → List Nat}
    {innerTag outerTag : Nat} {before after : State} {action : Action}
    (placement : ∀ iface, (expectedEncapStack iface).head? = some outerTag →
      expectedEncapStack iface = [outerTag, innerTag])
    (step : Step c before action after) (label : action = .encrypt)
    (added : after.frame.encapLayerIds = outerTag :: before.frame.encapLayerIds)
    (invariant : EncapStackConsistent c expectedEncapStack after) : before.frame.encapLayerIds = [innerTag] := by
  cases step <;> try cases label
  case encrypt iface frame authenticated association sa selected installed bound =>
    have tag : association.tag = outerTag := by
      have heads := congrArg List.head? added
      simpa [Frame.encapLayerIds, encrypt, IpsecPolicy.seal] using heads
    have head : (expectedEncapStack iface).head? = some outerTag := by
      rw [← invariant.1]
      change some association.tag = some outerTag
      rw [tag]
    have expected := placement iface head
    have shape : outerTag :: frame.encapLayerIds = [outerTag, innerTag] :=
      added.symm.trans (invariant.1.trans expected)
    exact (List.cons.inj shape).2

def OrderedEncryptions (c : DataPlaneModel) (innerTag outerTag : Nat)
    (before : State) (actions : List Action) (after : State) : Prop :=
  ∃ earlier later left action right,
    actions = earlier ++ action :: later ∧
    (lts c).MTr before earlier left ∧ Step c left action right ∧
    (lts c).MTr right later after ∧
    action = .encrypt ∧ right.frame.encapLayerIds = outerTag :: left.frame.encapLayerIds ∧
    left.frame.payload = before.frame.payload ∧
    TraceEvents.Contains (lts c) before earlier left
      (fun a label b => label = .encrypt ∧ b.frame.encapLayerIds = innerTag :: a.frame.encapLayerIds ∧
        a.frame.payload = before.frame.payload)

theorem nested_stack_requires_ordered_encryptions (c : DataPlaneModel) (expectedEncapStack : Nat → List Nat)
    (conditions : PerHopEncapConditions c expectedEncapStack) (innerTag outerTag : Nat)
    (placement : ∀ iface, (expectedEncapStack iface).head? = some outerTag →
      expectedEncapStack iface = [outerTag, innerTag])
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after) (initial : EncapStackConsistent c expectedEncapStack before)
    (empty : before.frame.encapLayerIds = []) (present : outerTag ∈ after.frame.encapLayerIds) :
    OrderedEncryptions c innerTag outerTag before actions after := by
  have absent : outerTag ∉ before.frame.encapLayerIds := by simp [empty]
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, label, added, payload⟩ :=
    boundary_layer_addition_has_encryption c outerTag run absent present
  have prefixInvariant := forwarding_preserves_encap_stack c expectedEncapStack conditions
    (first.stepR (lts c) step) initial
  have inner := outer_encryption_has_inner_stack placement step label added prefixInvariant
  have innerPresent : innerTag ∈ left.frame.encapLayerIds := by simp [inner]
  have innerAbsent : innerTag ∉ before.frame.encapLayerIds := by simp [empty]
  exact ⟨earlier, later, left, action, right, sequence, first, step, last, label, added, payload,
    boundary_layer_addition_has_encryption c innerTag first innerAbsent innerPresent⟩

end TDN.DataPlaneForwarding
