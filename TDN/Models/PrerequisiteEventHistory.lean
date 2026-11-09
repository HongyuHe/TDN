import Cslib.Foundations.Semantics.LTS.Basic

namespace TDN.Admission

inductive Step {Event : Type} (trigger : Event → Prop) (prerequisite : Event → Event → Prop) :
    List Event → Event → List Event → Prop
  | record (history : List Event) (event : Event)
      (guard : trigger event → ∃ prior ∈ history, prerequisite prior event) :
      Step trigger prerequisite history event (event :: history)

def lts {Event : Type} (trigger : Event → Prop) (prerequisite : Event → Event → Prop) :
    Cslib.LTS (List Event) Event := ⟨Step trigger prerequisite⟩

def HasPrerequisites {Event : Type} (trigger : Event → Prop) (prerequisite : Event → Event → Prop)
    (history : List Event) : Prop :=
  ∀ event ∈ history, trigger event → ∃ prior ∈ history, prerequisite prior event

lemma step_preserves_prerequisites {Event : Type} {trigger : Event → Prop}
    {prerequisite : Event → Event → Prop} {before after : List Event} {event : Event}
    (step : Step trigger prerequisite before event after)
    (valid : HasPrerequisites trigger prerequisite before) :
    HasPrerequisites trigger prerequisite after := by
  cases step with
  | record guard =>
    intro target member triggered
    rcases List.mem_cons.mp member with same | prior
    · subst target
      obtain ⟨witness, member, matched⟩ := guard triggered
      exact ⟨witness, List.mem_cons_of_mem _ member, matched⟩
    · obtain ⟨witness, member, matched⟩ := valid target prior triggered
      exact ⟨witness, List.mem_cons_of_mem _ member, matched⟩

theorem all_admitted_events_have_prerequisites {Event : Type}
    (trigger : Event → Prop) (prerequisite : Event → Event → Prop)
    {events : List Event} {history : List Event}
    (run : (lts trigger prerequisite).MTr [] events history) :
    HasPrerequisites trigger prerequisite history := by
  have preserved : (lts trigger prerequisite).TrInv (HasPrerequisites trigger prerequisite) :=
    fun _ _ _ step valid => step_preserves_prerequisites step valid
  exact Cslib.LTS.mtrInv_of_trInv preserved [] events history run (by simp [HasPrerequisites])

end TDN.Admission
