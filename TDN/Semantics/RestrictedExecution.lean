import TDN.Semantics.TraceEvents

namespace TDN.RestrictedExecution

/-- Restrict a traversal to states in one declared processing scope. A device-local traversal
ends at its egress; a later wire transfer belongs to the surrounding network execution. -/
def within {S A : Type} (system : Cslib.LTS S A) (scope : S → Prop) : Cslib.LTS S A where
  Tr := fun before action after => system.Tr before action after ∧ scope before ∧ scope after

theorem project_trace {S A : Type} (system : Cslib.LTS S A) (scope : S → Prop)
    {before after : S} {actions : List A}
    (run : (within system scope).MTr before actions after) :
    system.MTr before actions after := by
  induction run with
  | refl => exact .refl
  | stepL step rest ih => exact .stepL step.1 ih

theorem actual_event_in_scope {S A : Type} (system : Cslib.LTS S A) (scope : S → Prop)
    {before after : S} {actions : List A} {event : S → A → S → Prop}
    (found : TraceEvents.Contains (within system scope) before actions after event) :
    TraceEvents.Contains system before actions after
      (fun left action right => event left action right ∧ scope left ∧ scope right) := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, event⟩ := found
  exact ⟨earlier, later, left, action, right, sequence, project_trace system scope first,
    step.1, project_trace system scope last, event, step.2⟩

end TDN.RestrictedExecution
