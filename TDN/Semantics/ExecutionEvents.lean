import TDN.Semantics.ExecutionInvariant
import TDN.Semantics.TraceEvents

namespace TDN.Execution

lemma missing_tag_added_only_by_encryption {c : Config} {before after : State}
    {action : Action} {tag : Nat} (step : Step c before action after)
    (absent : tag ∉ before.frame.tags) (present : tag ∈ after.frame.tags) :
    action = .encrypt ∧ after.frame.tags = tag :: before.frame.tags := by
  cases step <;> try exact False.elim (absent present)
  case encrypt association sa selected installed bound =>
    change tag ∈ association.tag :: _ at present
    rcases List.mem_cons.mp present with head | tail
    · exact ⟨rfl, by rw [head]; rfl⟩
    · exact False.elim (absent tail)
  case decrypt association sa header rest tracking configured installed bound received outerSource outerDestination esp selected =>
    apply False.elim
    apply absent
    simp only [Frame.tags, received, List.map_cons]
    exact List.mem_cons_of_mem _ present

lemma present_tag_removed_only_by_decryption {c : Config} {before after : State}
    {action : Action} {tag : Nat} (step : Step c before action after)
    (present : tag ∈ before.frame.tags) (absent : tag ∉ after.frame.tags) :
    action = .decrypt ∧ before.frame.tags = tag :: after.frame.tags := by
  cases step <;> try exact False.elim (absent present)
  case encrypt association sa selected installed bound =>
    exact False.elim (absent (List.mem_cons_of_mem _ present))
  case decrypt association sa header rest tracking configured installed bound received outerSource outerDestination esp selected =>
    simp only [Frame.tags, received, List.map_cons] at present
    rcases List.mem_cons.mp present with head | tail
    · refine ⟨rfl, ?_⟩
      simp only [Frame.tags, received, List.map_cons]
      rw [head]
    · exact False.elim (absent tail)

lemma execution_payload_identity (c : Config) {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after) : after.frame.payload = before.frame.payload := by
  induction run with
  | refl => rfl
  | stepL step rest ih =>
    have same : _ := ih
    cases step <;> exact same

theorem boundary_layer_removal_has_decryption (c : Config) (tag : Nat)
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after)
    (initial : tag ∈ before.frame.tags) (final : tag ∉ after.frame.tags) :
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => action = .decrypt ∧
        left.frame.tags = tag :: right.frame.tags ∧ left.frame.payload = before.frame.payload) := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, present, absent⟩ :=
    TraceEvents.changing_predicate_has_event (lts c) (fun state => tag ∈ state.frame.tags)
      run initial final
  obtain ⟨label, removed⟩ := present_tag_removed_only_by_decryption step present absent
  exact ⟨earlier, later, left, action, right, sequence, first, step, last,
    label, removed, execution_payload_identity c first⟩

theorem boundary_layer_addition_has_encryption (c : Config) (tag : Nat)
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after)
    (initial : tag ∉ before.frame.tags) (final : tag ∈ after.frame.tags) :
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => action = .encrypt ∧
        right.frame.tags = tag :: left.frame.tags ∧ left.frame.payload = before.frame.payload) := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, absent, present⟩ :=
    TraceEvents.changing_predicate_has_event (lts c) (fun state => tag ∉ state.frame.tags)
      run initial (fun h => h final)
  have member : tag ∈ right.frame.tags := Classical.not_not.mp present
  obtain ⟨label, added⟩ := missing_tag_added_only_by_encryption step absent member
  exact ⟨earlier, later, left, action, right, sequence, first, step, last,
    label, added, execution_payload_identity c first⟩

lemma outer_encryption_has_inner_stack {c : Config} {layout : Nat → List Nat}
    {innerTag outerTag : Nat} {before after : State} {action : Action}
    (placement : ∀ port, (layout port).head? = some outerTag →
      layout port = [outerTag, innerTag])
    (step : Step c before action after) (label : action = .encrypt)
    (added : after.frame.tags = outerTag :: before.frame.tags)
    (invariant : StackInvariant c layout after) : before.frame.tags = [innerTag] := by
  cases step <;> try cases label
  case encrypt port frame authenticated association sa selected installed bound =>
    have tag : association.tag = outerTag := by
      have heads := congrArg List.head? added
      simpa [Frame.tags, encrypt, Association.seal] using heads
    have head : (layout port).head? = some outerTag := by
      rw [← invariant.1]
      change some association.tag = some outerTag
      rw [tag]
    have expected := placement port head
    have shape : outerTag :: frame.tags = [outerTag, innerTag] :=
      added.symm.trans (invariant.1.trans expected)
    exact (List.cons.inj shape).2

def OrderedEncryptions (c : Config) (innerTag outerTag : Nat)
    (before : State) (actions : List Action) (after : State) : Prop :=
  ∃ earlier later left action right,
    actions = earlier ++ action :: later ∧
    (lts c).MTr before earlier left ∧ Step c left action right ∧
    (lts c).MTr right later after ∧
    action = .encrypt ∧ right.frame.tags = outerTag :: left.frame.tags ∧
    left.frame.payload = before.frame.payload ∧
    TraceEvents.Contains (lts c) before earlier left
      (fun a label b => label = .encrypt ∧ b.frame.tags = innerTag :: a.frame.tags ∧
        a.frame.payload = before.frame.payload)

theorem nested_stack_requires_ordered_encryptions (c : Config) (layout : Nat → List Nat)
    (conditions : LocalStackConditions c layout) (innerTag outerTag : Nat)
    (placement : ∀ port, (layout port).head? = some outerTag →
      layout port = [outerTag, innerTag])
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after) (initial : StackInvariant c layout before)
    (empty : before.frame.tags = []) (present : outerTag ∈ after.frame.tags) :
    OrderedEncryptions c innerTag outerTag before actions after := by
  have absent : outerTag ∉ before.frame.tags := by simp [empty]
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, label, added, payload⟩ :=
    boundary_layer_addition_has_encryption c outerTag run absent present
  have prefixInvariant := execution_preserves_stack_invariant c layout conditions
    (first.stepR (lts c) step) initial
  have inner := outer_encryption_has_inner_stack placement step label added prefixInvariant
  have innerPresent : innerTag ∈ left.frame.tags := by simp [inner]
  have innerAbsent : innerTag ∉ before.frame.tags := by simp [empty]
  exact ⟨earlier, later, left, action, right, sequence, first, step, last, label, added, payload,
    boundary_layer_addition_has_encryption c innerTag first innerAbsent innerPresent⟩

end TDN.Execution
