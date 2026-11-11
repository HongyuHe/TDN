import TDN.Requirements.ProtectionLayerEventTrace

namespace TDN.Requirements.Msc
open Compliance

def OuterWrapsInner (outer inner : String) : List String → Prop
  | [] => False
  | tunnel :: rest => (tunnel = outer ∧ inner ∈ rest) ∨ OuterWrapsInner outer inner rest

lemma outer_wraps_inner_creation {payload : PayloadId} {before after : List String}
    {event : NetworkEvent} {outer inner : String}
    (step : ProtectionLayerStep payload before event after)
    (missing : ¬ OuterWrapsInner outer inner before)
    (present : OuterWrapsInner outer inner after) :
    event = .encrypt payload outer ∧ inner ∈ before := by
  cases step with
  | encrypt layers tunnel =>
    rcases present with added | previous
    · exact ⟨congrArg (NetworkEvent.encrypt payload) added.1, added.2⟩
    · exact False.elim (missing previous)
  | decrypt layers tunnel => exact False.elim (missing (Or.inr present))
  | transmit | receive | neutral => exact False.elim (missing present)

lemma event_member_has_segments {event : NetworkEvent} {events : List NetworkEvent}
    (member : event ∈ events) : ∃ earlier later, events = earlier ++ [event] ++ later := by
  induction events with
  | nil => cases member
  | cons first rest ih =>
    rcases List.mem_cons.mp member with same | tail
    · subst first; exact ⟨[], rest, rfl⟩
    · obtain ⟨earlier, later, split⟩ := ih tail
      exact ⟨first :: earlier, later, congrArg (first :: ·) split⟩

theorem nested_tunnel_names_require_ordered_encryptions {payload : PayloadId}
    {events : List NetworkEvent} {layers : List String} {outer inner : String}
    (run : (protectionLayerSystem payload).MTr [] events layers)
    (nested : OuterWrapsInner outer inner layers) :
    Before events (.encrypt payload inner) (.encrypt payload outer) := by
  obtain ⟨earlier, later, left, event, right, sequence, first, step, last, missing, found⟩ :=
    TraceEvents.changing_predicate_has_event (protectionLayerSystem payload)
      (fun stack => ¬ OuterWrapsInner outer inner stack) run (by simp [OuterWrapsInner])
      (fun absent => absent nested)
  obtain ⟨operation, innerPresent⟩ := outer_wraps_inner_creation step missing (Classical.not_not.mp found)
  have encrypted := event_layers_addition_has_encrypt first (by simp) innerPresent
  obtain ⟨leading, middle, split⟩ := event_member_has_segments encrypted
  refine ⟨leading, middle, later, ?_⟩
  rw [sequence, operation, split]
  simp only [List.append_assoc, List.singleton_append]

def reverseProtectionEvent : NetworkEvent → NetworkEvent
  | .encrypt payload tunnel => .decrypt payload tunnel
  | .decrypt payload tunnel => .encrypt payload tunnel
  | event => event

lemma reverse_protection_event_twice (event : NetworkEvent) :
    reverseProtectionEvent (reverseProtectionEvent event) = event := by
  cases event <;> rfl

lemma protection_layer_step_reversed {payload : PayloadId} {before after : List String}
    {event : NetworkEvent} (step : ProtectionLayerStep payload before event after) :
    ProtectionLayerStep payload after (reverseProtectionEvent event) before := by
  cases step with
  | encrypt => exact .decrypt _ _
  | decrypt => exact .encrypt _ _
  | transmit => exact .transmit _ _ _
  | receive => exact .receive _ _ _
  | neutral _ event ignored =>
    apply ProtectionLayerStep.neutral
    cases event <;> simp_all [ProtectionLayerNeutral, reverseProtectionEvent]

lemma protection_layer_trace_reversed {payload : PayloadId} {before after : List String}
    {events : List NetworkEvent} (run : (protectionLayerSystem payload).MTr before events after) :
    (protectionLayerSystem payload).MTr after (events.reverse.map reverseProtectionEvent) before := by
  induction run with
  | refl => exact .refl
  | @stepL first event next rest last step tail ih =>
    have appended := (Cslib.LTS.MTr.append_iff (protectionLayerSystem payload)).mpr
      ⟨next, ih, .stepL (protection_layer_step_reversed step) .refl⟩
    simpa only [List.reverse_cons, List.map_append, List.map_singleton] using appended

lemma reversed_encryptions_are_ordered_decryptions {events : List NetworkEvent}
    {payload : PayloadId} {outer inner : String}
    (ordered : Before (events.reverse.map reverseProtectionEvent)
      (.encrypt payload inner) (.encrypt payload outer)) :
    Before events (.decrypt payload outer) (.decrypt payload inner) := by
  obtain ⟨earlier, middle, later, sequence⟩ := ordered
  refine ⟨later.reverse.map reverseProtectionEvent, middle.reverse.map reverseProtectionEvent,
    earlier.reverse.map reverseProtectionEvent, ?_⟩
  have reversed := congrArg (fun trace => (trace.map reverseProtectionEvent).reverse) sequence
  simp only [List.map_map, Function.comp_def, reverse_protection_event_twice] at reversed
  simpa [List.reverse_append, List.map_reverse, reverseProtectionEvent, List.append_assoc] using reversed

theorem nested_tunnel_names_require_ordered_decryptions {payload : PayloadId}
    {events : List NetworkEvent} {layers : List String} {outer inner : String}
    (run : (protectionLayerSystem payload).MTr layers events [])
    (nested : OuterWrapsInner outer inner layers) :
    Before events (.decrypt payload outer) (.decrypt payload inner) := by
  exact reversed_encryptions_are_ordered_decryptions
    (nested_tunnel_names_require_ordered_encryptions (protection_layer_trace_reversed run) nested)

end TDN.Requirements.Msc
