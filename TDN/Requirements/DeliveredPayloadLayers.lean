import TDN.Requirements.DeviceProtectionLayerEvents
import TDN.Requirements.NestedProtectionEventOrder

namespace TDN.Requirements.Msc
open Compliance LayeredFrame MultiProtocolForwarding

def DeliveryLayerNeutral : NetworkEvent → Prop
  | .encrypt .. | .decrypt .. | .transmit .. | .receive .. | .deliver .. => False
  | _ => True

inductive DeliveryLayerStep (payload : PayloadId) : List String → NetworkEvent → List String → Prop
  | encrypt (layers : List String) (tunnel : String) :
      DeliveryLayerStep payload layers (.encrypt payload tunnel) (tunnel :: layers)
  | decrypt (layers : List String) (tunnel : String) :
      DeliveryLayerStep payload (tunnel :: layers) (.decrypt payload tunnel) layers
  | transmit (layers : List String) (iface : String) (trafficClass : TrafficClass) :
      DeliveryLayerStep payload layers (.transmit payload iface layers trafficClass) layers
  | receive (layers : List String) (iface : String) (trafficClass : TrafficClass) :
      DeliveryLayerStep payload layers (.receive payload iface layers trafficClass) layers
  | deliver (layers : List String) (network : String) :
      DeliveryLayerStep payload layers (.deliver payload network layers) layers
  | neutral (layers : List String) (event : NetworkEvent) (ignored : DeliveryLayerNeutral event) :
      DeliveryLayerStep payload layers event layers

def deliveryLayerSystem (payload : PayloadId) : Cslib.LTS (List String) NetworkEvent :=
  ⟨DeliveryLayerStep payload⟩

lemma delivery_layer_step_tracks_protection {payload : PayloadId} {before after : List String}
    {event : NetworkEvent} (step : DeliveryLayerStep payload before event after) :
    ProtectionLayerStep payload before event after := by
  cases step with
  | encrypt => exact .encrypt _ _
  | decrypt => exact .decrypt _ _
  | transmit => exact .transmit _ _ _
  | receive => exact .receive _ _ _
  | deliver => exact .neutral _ _ trivial
  | neutral _ event ignored =>
    apply ProtectionLayerStep.neutral
    cases event <;> simp_all [DeliveryLayerNeutral, ProtectionLayerNeutral]

lemma delivery_layer_trace_tracks_protection {payload : PayloadId} {before after : List String}
    {events : List NetworkEvent} (run : (deliveryLayerSystem payload).MTr before events after) :
    (protectionLayerSystem payload).MTr before events after := by
  induction run with
  | refl => exact .refl
  | stepL step tail ih => exact .stepL (delivery_layer_step_tracks_protection step) ih

lemma delivery_layer_run_from_network_filter {payload : PayloadId} {events : List NetworkEvent}
    {before after : List String}
    (run : (deliveryLayerSystem payload).MTr before
      (events.filter NetworkEvent.NetworkOperation) after) :
    (deliveryLayerSystem payload).MTr before events after := by
  induction events generalizing before with
  | nil => exact run
  | cons event rest ih =>
    cases selected : event.NetworkOperation with
    | false =>
      have tail : (deliveryLayerSystem payload).MTr before
          (rest.filter NetworkEvent.NetworkOperation) after := by
        simpa only [List.filter_cons, selected, Bool.false_eq_true, ↓reduceIte] using run
      have ignored : DeliveryLayerNeutral event := by
        cases event <;> simp_all [NetworkEvent.NetworkOperation, DeliveryLayerNeutral]
      exact .stepL (DeliveryLayerStep.neutral before event ignored) (ih tail)
    | true =>
      have whole : (deliveryLayerSystem payload).MTr before
          (event :: rest.filter NetworkEvent.NetworkOperation) after := by
        simpa only [List.filter_cons, selected, ↓reduceIte] using run
      cases whole with
      | stepL step tail => exact .stepL step (ih tail)

lemma delivery_neutral_events_preserve_layers {payload : PayloadId} (layers : List String)
    (events : List NetworkEvent) (neutral : ∀ event ∈ events, DeliveryLayerNeutral event) :
    (deliveryLayerSystem payload).MTr layers events layers := by
  induction events with
  | nil => exact .refl
  | cons event rest ih =>
    exact .stepL (DeliveryLayerStep.neutral layers event (neutral event (by simp)))
      (ih (fun next member => neutral next (by simp [member])))

lemma delivery_layer_deliver_shape {payload observed : PayloadId} {before after layers : List String}
    {network : String} (step : DeliveryLayerStep payload before (.deliver observed network layers) after) :
    observed = payload ∧ before = layers ∧ after = layers := by
  cases step with
  | deliver => exact ⟨rfl, rfl, rfl⟩
  | neutral layers event ignored => cases ignored

lemma device_source_events_follow_delivery_layers {S A : Type} (binding : DeviceExecutionBinding S A)
    (before : S) :
    (deliveryLayerSystem ⟨(binding.state before).frame.originDomain, (binding.state before).frame.payload⟩).MTr
      (binding.LayerIds (binding.state before).frame.body) (binding.SourceEvents before)
      (binding.LayerIds (binding.state before).frame.body) := by
  dsimp only [DeviceExecutionBinding.SourceEvents]
  split
  next initial =>
    cases origin : binding.origin (binding.state before).frame.originDomain with
    | red network =>
      dsimp only
      split
      next checked =>
        rw [checked.2]
        exact .stepL (DeliveryLayerStep.neutral [] _ trivial) (.stepL (DeliveryLayerStep.receive [] _ _) .refl)
      next missing => exact .refl
    | management component => exact .refl
    | control component protocol => exact .refl
  next other => exact .refl

lemma device_operation_events_follow_delivery_layers {S A : Type} (binding : DeviceExecutionBinding S A)
    {before after : MultiProtocolForwarding.State} {action : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before action after) :
    (deliveryLayerSystem ⟨before.frame.originDomain, before.frame.payload⟩).MTr
      (binding.LayerIds before.frame.body)
      ((binding.withProjection id (fun operation => some operation)).OperationEvents before action after)
      (binding.LayerIds after.frame.body) := by
  have names : ∀ body, (binding.withProjection (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
      (fun operation : MultiProtocolForwarding.Action => some operation)).LayerIds body = binding.LayerIds body :=
    layer_ids_with_tunnel_names binding _ _
  dsimp only [DeviceExecutionBinding.withProjection] at names
  dsimp only [DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq]
  cases step <;> simp only [Config.forwardedFrame_body, Config.ipsecFrame_body,
    Config.macsecFrame_body, Config.macsec_pdu_frame_body, Config.carrierFrame_body,
    Config.restoredFrame_body, DeviceExecutionBinding.LayerIds]
  all_goals try simp only [names]
  all_goals try simp_all only [DeviceExecutionBinding.LayerIds]
  all_goals try {
    repeat' first
      | exact Cslib.LTS.MTr.refl
      | apply Cslib.LTS.MTr.stepL
      | exact DeliveryLayerStep.encrypt _ _
      | exact DeliveryLayerStep.decrypt _ _
      | exact DeliveryLayerStep.transmit _ _ _
      | exact DeliveryLayerStep.receive _ _ _
      | exact DeliveryLayerStep.deliver _ _
      | exact DeliveryLayerStep.neutral _ _ (by trivial) }
  all_goals try {
    have same := carrier_unwrap_preserves_tunnel_names binding _ _ _ _ _ _ _ ‹_›
    rw [same]
    split <;> first
      | exact Cslib.LTS.MTr.refl
      | exact .stepL (DeliveryLayerStep.neutral _ _ (by trivial)) .refl }

lemma device_required_events_follow_delivery_layers {S A : Type} (binding : DeviceExecutionBinding S A)
    {before after : S} {action : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration (binding.state before) action (binding.state after)) :
    (deliveryLayerSystem ⟨(binding.state before).frame.originDomain, (binding.state before).frame.payload⟩).MTr
      (binding.LayerIds (binding.state before).frame.body) (binding.RequiredEvents before action after)
      (binding.LayerIds (binding.state after).frame.body) := by
  apply (Cslib.LTS.MTr.append_iff _).mpr
  refine ⟨_, device_source_events_follow_delivery_layers binding before, ?_⟩
  have names : ∀ body, (binding.withProjection (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
      (fun operation : MultiProtocolForwarding.Action => some operation)).LayerIds body = binding.LayerIds body :=
    layer_ids_with_tunnel_names binding _ _
  dsimp only [DeviceExecutionBinding.withProjection] at names
  simpa only [DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq, names]
    using device_operation_events_follow_delivery_layers binding step

lemma delivery_required_events_with_tunnel_names {S A : Type} (binding : DeviceExecutionBinding S A)
    (before after : S) (operation : MultiProtocolForwarding.Action) :
    (binding.withProjection (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
      (fun action : MultiProtocolForwarding.Action => some action)).RequiredEvents
        (binding.state before) operation (binding.state after) = binding.RequiredEvents before operation after := by
  have names : ∀ body, (binding.withProjection (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
      (fun action : MultiProtocolForwarding.Action => some action)).LayerIds body = binding.LayerIds body :=
    layer_ids_with_tunnel_names binding _ _
  dsimp only [DeviceExecutionBinding.withProjection] at names
  simp only [DeviceExecutionBinding.RequiredEvents, DeviceExecutionBinding.SourceEvents,
    DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq, names]

lemma model_step_events_follow_delivery_layers {S A : Type} (model : ForwardingModel S A)
    (faithful : model.Faithful) {before after : S} {action : A}
    (step : model.system.Tr before action after) :
    (deliveryLayerSystem ⟨(model.native.state before).frame.originDomain,
      (model.native.state before).frame.payload⟩).MTr
      (model.native.LayerIds (model.native.state before).frame.body) (model.events action)
      (model.native.LayerIds (model.native.state after).frame.body) := by
  apply delivery_layer_run_from_network_filter
  have checked := faithful before action after step
  cases selected : model.native.action action with
  | none =>
    rw [selected] at checked
    rw [checked.2, ← checked.1]
    exact .refl
  | some operation =>
    rw [selected] at checked
    rw [checked.2]
    exact device_required_events_follow_delivery_layers model.native checked.1.1

lemma forwarding_events_follow_delivery_layers {S A : Type} (model : ForwardingModel S A)
    (faithful : model.Faithful) {before after : S} {actions : List A}
    (run : model.system.MTr before actions after) :
    (deliveryLayerSystem ⟨(model.native.state before).frame.originDomain,
      (model.native.state before).frame.payload⟩).MTr
      (model.native.LayerIds (model.native.state before).frame.body) (actions.flatMap model.events)
      (model.native.LayerIds (model.native.state after).frame.body) := by
  induction run with
  | refl => exact .refl
  | @stepL first operation next rest last step tail ih =>
    have identity := model.preserves_payload_identity faithful (Cslib.LTS.MTr.stepL step .refl)
    rw [identity.1, identity.2] at ih
    exact (Cslib.LTS.MTr.append_iff _).mpr
      ⟨_, model_step_events_follow_delivery_layers model faithful step, ih⟩

lemma setup_history_events_preserve_delivery_layers (history : ObservedHistory) (valid : history.Valid)
    (payload : PayloadId) (layers : List String) :
    (deliveryLayerSystem payload).MTr layers history.Events layers := by
  apply delivery_neutral_events_preserve_layers
  intro event member
  obtain ⟨record, stored, same⟩ := List.mem_map.mp member
  have setup := (valid.2.1 record stored).2.2.2.2
  rw [← same]
  rcases record with ⟨source, observer, localPosition, component, position, epoch, session, recorded⟩
  cases recorded <;> simp_all [HistoricalEvent.SetupOnly, DeliveryLayerNeutral]

lemma delivery_initial_source_has_no_layers {S A : Type} (model : ForwardingModel S A) (d : Deployment)
    (source : model.SourceCoverage d) {start : S} (initial : model.initial start) :
    model.native.LayerIds (model.native.state start).frame.body = [] := by
  have plain := (source.2.2.2.1 start initial).1.2.1
  rcases plain with ⟨header, same⟩ | ⟨header, same⟩ <;>
    simp only [same, DeviceExecutionBinding.LayerIds]

lemma deployment_events_follow_delivery_layers {S A : Type} (model : ForwardingModel S A) (d : Deployment)
    (covered : model.CoversDeployment d) {start finish : S} {actions : List A}
    (initial : model.initial start) (run : model.system.MTr start actions finish) :
    (deliveryLayerSystem ⟨(model.native.state start).frame.originDomain,
      (model.native.state start).frame.payload⟩).MTr [] (model.TraceEvents actions)
      (model.native.LayerIds (model.native.state finish).frame.body) := by
  have following := forwarding_events_follow_delivery_layers model covered.2.1 run
  rw [delivery_initial_source_has_no_layers model d covered.2.2.2.1 initial] at following
  exact (Cslib.LTS.MTr.append_iff _).mpr
    ⟨[], setup_history_events_preserve_delivery_layers model.history covered.2.2.2.2.1 _ [], following⟩

lemma delivery_trace_before_transmit {payload observed : PayloadId} {before after layers : List String}
    {events earlier later : List NetworkEvent} {iface : String} {trafficClass : TrafficClass}
    (run : (deliveryLayerSystem payload).MTr before events after)
    (split : events = earlier ++ [.transmit observed iface layers trafficClass] ++ later) :
    observed = payload ∧ (deliveryLayerSystem payload).MTr before earlier layers := by
  rw [split] at run
  simp only [List.append_assoc, List.singleton_append] at run
  obtain ⟨left, right, leadingRun, step, suffix⟩ := event_trace_split _ run
  have shape := protection_layer_transmit_shape (delivery_layer_step_tracks_protection step)
  exact ⟨shape.1, shape.2.1 ▸ leadingRun⟩

lemma delivery_trace_before_deliver {payload observed : PayloadId} {before after layers : List String}
    {events earlier later : List NetworkEvent} {network : String}
    (run : (deliveryLayerSystem payload).MTr before events after)
    (split : events = earlier ++ [.deliver observed network layers] ++ later) :
    observed = payload ∧ (deliveryLayerSystem payload).MTr before earlier layers := by
  rw [split] at run
  simp only [List.append_assoc, List.singleton_append] at run
  obtain ⟨left, right, leadingRun, step, suffix⟩ := event_trace_split _ run
  have shape := delivery_layer_deliver_shape step
  exact ⟨shape.1, shape.2.1 ▸ leadingRun⟩

lemma events_before_black_transmit_deliver_after_outer_then_inner {payload : PayloadId}
    {events beforeCross afterCross : List NetworkEvent} {iface : String} {trafficClass : TrafficClass}
    {outer inner : String} {layers : List String}
    (run : (deliveryLayerSystem payload).MTr layers events [])
    (split : events = beforeCross ++ [.transmit payload iface [outer, inner] trafficClass] ++ afterCross) :
    Before events (.decrypt payload outer) (.decrypt payload inner) := by
  rw [split] at run
  simp only [List.append_assoc, List.singleton_append] at run
  obtain ⟨left, right, leadingRun, step, suffix⟩ := event_trace_split _ run
  have shape := protection_layer_transmit_shape (delivery_layer_step_tracks_protection step)
  rw [shape.2.2] at suffix
  have ordered := nested_tunnel_names_require_ordered_decryptions (outer := outer) (inner := inner)
    (delivery_layer_trace_tracks_protection suffix) (by simp [OuterWrapsInner])
  obtain ⟨earlier, middle, later, sequence⟩ := ordered
  refine ⟨beforeCross ++ [.transmit payload iface [outer, inner] trafficClass] ++ earlier,
    middle, later, ?_⟩
  rw [split, sequence]
  simp only [List.append_assoc]

lemma events_before_black_receive_deliver_after_outer_then_inner {payload : PayloadId}
    {events beforeCross afterCross : List NetworkEvent} {iface : String} {trafficClass : TrafficClass}
    {outer inner : String} {layers : List String}
    (run : (deliveryLayerSystem payload).MTr layers events [])
    (split : events = beforeCross ++ [.receive payload iface [outer, inner] trafficClass] ++ afterCross) :
    Before events (.decrypt payload outer) (.decrypt payload inner) := by
  rw [split] at run
  simp only [List.append_assoc, List.singleton_append] at run
  obtain ⟨left, right, leadingRun, step, suffix⟩ := event_trace_split _ run
  have shape := protection_layer_receive_shape (delivery_layer_step_tracks_protection step)
  rw [shape.2.2] at suffix
  have ordered := nested_tunnel_names_require_ordered_decryptions (outer := outer) (inner := inner)
    (delivery_layer_trace_tracks_protection suffix) (by simp [OuterWrapsInner])
  obtain ⟨earlier, middle, later, sequence⟩ := ordered
  refine ⟨beforeCross ++ [.receive payload iface [outer, inner] trafficClass] ++ earlier,
    middle, later, ?_⟩
  rw [split, sequence]
  simp only [List.append_assoc]

end TDN.Requirements.Msc
