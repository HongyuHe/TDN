import Cslib.Foundations.Semantics.LTS.Basic

namespace TDN.TraceEvents

/-- An event occurrence includes the actual states and trace prefix/suffix, not only a label. -/
def Contains {State Action : Type} (system : Cslib.LTS State Action)
    (before : State) (actions : List Action) (after : State)
    (event : State → Action → State → Prop) : Prop :=
  ∃ earlier later left action right,
    actions = earlier ++ action :: later ∧
    system.MTr before earlier left ∧ system.Tr left action right ∧
    system.MTr right later after ∧ event left action right

/-- A predicate that changes across an execution must change at one of its actual steps. -/
theorem changing_predicate_has_event {State Action : Type}
    (system : Cslib.LTS State Action) (predicate : State → Prop)
    {before after : State} {actions : List Action}
    (run : system.MTr before actions after)
    (initial : predicate before) (final : ¬ predicate after) :
    Contains system before actions after
      (fun left _ right => predicate left ∧ ¬ predicate right) := by
  classical
  induction run with
  | refl => exact False.elim (final initial)
  | @stepL start action next actions finish step rest ih =>
    by_cases holds : predicate next
    · obtain ⟨earlier, later, left, chosen, right, sequence, first, middle, last, event⟩ :=
        ih holds final
      exact ⟨action :: earlier, later, left, chosen, right, by simp [sequence],
        .stepL step first, middle, last, event⟩
    · exact ⟨[], actions, start, action, next, rfl, .refl, step, rest, initial, holds⟩

theorem map_event {State Action : Type} (system : Cslib.LTS State Action)
    {before after : State} {actions : List Action}
    {first second : State → Action → State → Prop}
    (found : Contains system before actions after first)
    (convert : ∀ left action right, system.Tr left action right →
      first left action right → second left action right) :
    Contains system before actions after second := by
  obtain ⟨earlier, later, left, action, right, sequence, start, step, finish, event⟩ := found
  exact ⟨earlier, later, left, action, right, sequence, start, step, finish,
    convert left action right step event⟩

end TDN.TraceEvents
