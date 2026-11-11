import TDN.Requirements.NetworkEventTraceSegments
import TDN.Models.LocateTransitionStepInTrace

namespace TDN.Requirements.Msc
open Compliance

def ProtectionLayerNeutral : NetworkEvent → Prop
  | .encrypt .. | .decrypt .. | .transmit .. | .receive .. => False
  | _ => True

inductive ProtectionLayerStep (payload : PayloadId) : List String → NetworkEvent → List String → Prop
  | encrypt (layers : List String) (tunnel : String) :
      ProtectionLayerStep payload layers (.encrypt payload tunnel) (tunnel :: layers)
  | decrypt (layers : List String) (tunnel : String) :
      ProtectionLayerStep payload (tunnel :: layers) (.decrypt payload tunnel) layers
  | transmit (layers : List String) (iface : String) (trafficClass : TrafficClass) :
      ProtectionLayerStep payload layers (.transmit payload iface layers trafficClass) layers
  | receive (layers : List String) (iface : String) (trafficClass : TrafficClass) :
      ProtectionLayerStep payload layers (.receive payload iface layers trafficClass) layers
  | neutral (layers : List String) (event : NetworkEvent) (ignored : ProtectionLayerNeutral event) :
      ProtectionLayerStep payload layers event layers

def protectionLayerSystem (payload : PayloadId) : Cslib.LTS (List String) NetworkEvent :=
  ⟨ProtectionLayerStep payload⟩

lemma protection_layer_addition_requires_encrypt {payload : PayloadId} {before after : List String}
    {event : NetworkEvent} {tunnel : String} (step : ProtectionLayerStep payload before event after)
    (absent : tunnel ∉ before) (present : tunnel ∈ after) : event = .encrypt payload tunnel := by
  cases step with
  | encrypt layers added =>
    rcases List.mem_cons.mp present with equal | member
    · exact congrArg (NetworkEvent.encrypt payload) equal.symm
    · exact False.elim (absent member)
  | decrypt layers removed => exact False.elim (absent (List.mem_cons_of_mem removed present))
  | transmit | receive | neutral => exact False.elim (absent present)

lemma protection_layer_removal_requires_decrypt {payload : PayloadId} {before after : List String}
    {event : NetworkEvent} {tunnel : String} (step : ProtectionLayerStep payload before event after)
    (present : tunnel ∈ before) (absent : tunnel ∉ after) : event = .decrypt payload tunnel := by
  cases step with
  | encrypt layers added => exact False.elim (absent (List.mem_cons_of_mem added present))
  | decrypt layers removed =>
    rcases List.mem_cons.mp present with equal | member
    · exact congrArg (NetworkEvent.decrypt payload) equal.symm
    · exact False.elim (absent member)
  | transmit | receive | neutral => exact False.elim (absent present)

theorem event_layers_addition_has_encrypt {payload : PayloadId} {before after : List String}
    {events : List NetworkEvent} {tunnel : String}
    (run : (protectionLayerSystem payload).MTr before events after)
    (absent : tunnel ∉ before) (present : tunnel ∈ after) : .encrypt payload tunnel ∈ events := by
  obtain ⟨earlier, later, left, event, right, sequence, first, step, last, missing, found⟩ :=
    TraceEvents.changing_predicate_has_event (protectionLayerSystem payload)
      (fun layers => tunnel ∉ layers) run absent (fun valid => valid present)
  have equal := protection_layer_addition_requires_encrypt step missing (Classical.not_not.mp found)
  rw [sequence, equal]
  simp

theorem event_layers_removal_has_decrypt {payload : PayloadId} {before after : List String}
    {events : List NetworkEvent} {tunnel : String}
    (run : (protectionLayerSystem payload).MTr before events after)
    (present : tunnel ∈ before) (absent : tunnel ∉ after) : .decrypt payload tunnel ∈ events := by
  obtain ⟨earlier, later, left, event, right, sequence, first, step, last, found, missing⟩ :=
    TraceEvents.changing_predicate_has_event (protectionLayerSystem payload)
      (fun layers => tunnel ∈ layers) run present absent
  have equal := protection_layer_removal_requires_decrypt step found missing
  rw [sequence, equal]
  simp

lemma nonnetwork_event_is_layer_neutral (event : NetworkEvent)
    (absent : event.NetworkOperation = false) : ProtectionLayerNeutral event := by
  cases event <;> simp_all [NetworkEvent.NetworkOperation, ProtectionLayerNeutral]

theorem layer_run_from_network_filter {payload : PayloadId} {events : List NetworkEvent}
    {before after : List String}
    (run : (protectionLayerSystem payload).MTr before
      (events.filter NetworkEvent.NetworkOperation) after) :
    (protectionLayerSystem payload).MTr before events after := by
  induction events generalizing before with
  | nil => exact run
  | cons event rest ih =>
    cases selected : event.NetworkOperation with
    | false =>
      have tail : (protectionLayerSystem payload).MTr before
          (rest.filter NetworkEvent.NetworkOperation) after := by
        simpa only [List.filter_cons, selected, Bool.false_eq_true, ↓reduceIte] using run
      exact .stepL (ProtectionLayerStep.neutral before event (nonnetwork_event_is_layer_neutral event selected))
        (ih tail)
    | true =>
      have whole : (protectionLayerSystem payload).MTr before
          (event :: rest.filter NetworkEvent.NetworkOperation) after := by
        simpa only [List.filter_cons, selected, ↓reduceIte] using run
      cases whole with
      | stepL step tail => exact .stepL step (ih tail)

lemma neutral_events_preserve_layers {payload : PayloadId} (layers : List String)
    (events : List NetworkEvent) (neutral : ∀ event ∈ events, ProtectionLayerNeutral event) :
    (protectionLayerSystem payload).MTr layers events layers := by
  induction events with
  | nil => exact .refl
  | cons event rest ih =>
    exact .stepL (ProtectionLayerStep.neutral layers event (neutral event (by simp)))
      (ih (fun next member => neutral next (by simp [member])))

lemma event_trace_split {S A : Type} (system : Cslib.LTS S A)
    {start finish : S} {earlier later : List A} {action : A}
    (run : system.MTr start (earlier ++ action :: later) finish) :
    ∃ before after, system.MTr start earlier before ∧ system.Tr before action after ∧
      system.MTr after later finish := by
  obtain ⟨before, first, rest⟩ := (Cslib.LTS.MTr.append_iff system).mp run
  cases rest with
  | stepL step tail => exact ⟨before, _, first, step, tail⟩

lemma protection_layer_receive_shape {payload observed : PayloadId} {before after layers : List String}
    {iface : String} {trafficClass : TrafficClass}
    (step : ProtectionLayerStep payload before (.receive observed iface layers trafficClass) after) :
    observed = payload ∧ before = layers ∧ after = layers := by
  cases step with
  | receive => exact ⟨rfl, rfl, rfl⟩
  | neutral layers event ignored => cases ignored

lemma protection_layer_transmit_shape {payload observed : PayloadId} {before after layers : List String}
    {iface : String} {trafficClass : TrafficClass}
    (step : ProtectionLayerStep payload before (.transmit observed iface layers trafficClass) after) :
    observed = payload ∧ before = layers ∧ after = layers := by
  cases step with
  | transmit => exact ⟨rfl, rfl, rfl⟩
  | neutral layers event ignored => cases ignored

lemma receive_to_transmit_layer_run {payload : PayloadId} {start finish received sent : List String}
    {earlier middle later : List NetworkEvent} {ingress egress : String}
    {receiveClass sendClass : TrafficClass}
    (run : (protectionLayerSystem payload).MTr start
      (earlier ++ [.receive payload ingress received receiveClass] ++ middle ++
        [.transmit payload egress sent sendClass] ++ later) finish) :
    (protectionLayerSystem payload).MTr received middle sent := by
  have firstSplit : (protectionLayerSystem payload).MTr start
      (earlier ++ .receive payload ingress received receiveClass ::
        (middle ++ .transmit payload egress sent sendClass :: later)) finish := by
    simpa only [List.append_assoc, List.singleton_append, List.cons_append, List.nil_append] using run
  obtain ⟨before, after, leadingRun, receivedStep, suffix⟩ := event_trace_split _ firstSplit
  have receivedShape := protection_layer_receive_shape receivedStep
  obtain ⟨left, right, between, sentStep, trailing⟩ := event_trace_split _ suffix
  have sentShape := protection_layer_transmit_shape sentStep
  simpa only [receivedShape.2.2, sentShape.2.1] using between

end TDN.Requirements.Msc
