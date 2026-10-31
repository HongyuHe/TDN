import TDN.Semantics.Temporal

namespace TDN.GuardedEvents

/-- Each newly admitted event checks its prerequisite against the already recorded history. -/
inductive History (trigger prerequisite : String) : List Temporal.Event → Prop
  | empty : History trigger prerequisite []
  | record {events : List Temporal.Event} (event : Temporal.Event)
      (previous : History trigger prerequisite events)
      (guard : event.kind = trigger → Temporal.Prior events prerequisite event) :
      History trigger prerequisite (event :: events)

lemma prior_survives_record {events : List Temporal.Event} {kind : String}
    {event : Temporal.Event} (newEvent : Temporal.Event)
    (prior : Temporal.Prior events kind event) :
    Temporal.Prior (newEvent :: events) kind event := by
  obtain ⟨w, hw, hk, ho, ht⟩ := prior
  exact ⟨w, by simp [hw], hk, ho, ht⟩

/-- Admission-time prerequisite checks imply the global before-event property for every record. -/
theorem all_recorded_events_have_prerequisites {trigger prerequisite : String}
    {events : List Temporal.Event} (history : History trigger prerequisite events) :
    ∀ event ∈ events, event.kind = trigger → Temporal.Prior events prerequisite event := by
  induction history with
  | empty => simp
  | @record events event previous guard ih =>
    intro target member triggered
    rcases List.mem_cons.mp member with same | earlier
    · subst target
      exact prior_survives_record event (guard triggered)
    · exact prior_survives_record event (ih target earlier triggered)

end TDN.GuardedEvents
