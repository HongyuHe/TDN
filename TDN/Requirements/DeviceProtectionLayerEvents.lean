import TDN.Requirements.ProtectionLayerEventTrace
import TDN.Requirements.DataPlaneToEventTraceBridge

namespace TDN.Requirements.Msc
open Compliance LayeredFrame MultiProtocolForwarding

lemma carrier_unwrap_preserves_tunnel_names {S A : Type} (binding : DeviceExecutionBinding S A)
    (localAddress remote sourcePort destinationPort localSession : Nat) {protocol networkProtocol : String}
    (before after : Body)
    (unwrapped : unwrapCarrier localAddress remote sourcePort destinationPort localSession before protocol networkProtocol = some after) :
    binding.LayerIds after = binding.LayerIds before := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    next matched => cases unwrapped; rfl
    next missed => cases unwrapped

lemma layer_ids_with_tunnel_names {S A T B : Type} (binding : DeviceExecutionBinding S A)
    (state : T → MultiProtocolForwarding.State) (action : B → Option MultiProtocolForwarding.Action)
    (body : Body) : (binding.withProjection state action).LayerIds body = binding.LayerIds body := by
  induction body <;> simp_all [DeviceExecutionBinding.LayerIds, DeviceExecutionBinding.withProjection]

lemma device_source_events_follow_layers {S A : Type} (binding : DeviceExecutionBinding S A)
    (before : S) :
    (protectionLayerSystem ⟨(binding.state before).frame.originDomain, (binding.state before).frame.payload⟩).MTr
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
        exact .stepL (ProtectionLayerStep.neutral [] _ trivial) (.stepL (ProtectionLayerStep.receive [] _ _) .refl)
      next missing => exact .refl
    | management component => exact .refl
    | control component protocol => exact .refl
  next other => exact .refl

lemma device_operation_events_follow_layers {S A : Type} (binding : DeviceExecutionBinding S A)
    {before after : MultiProtocolForwarding.State} {action : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before action after) :
    (protectionLayerSystem ⟨before.frame.originDomain, before.frame.payload⟩).MTr
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
      | exact ProtectionLayerStep.encrypt _ _
      | exact ProtectionLayerStep.decrypt _ _
      | exact ProtectionLayerStep.transmit _ _ _
      | exact ProtectionLayerStep.receive _ _ _
      | exact ProtectionLayerStep.neutral _ _ (by trivial) }
  all_goals try {
    have same := carrier_unwrap_preserves_tunnel_names binding _ _ _ _ _ _ _ ‹_›
    rw [same]
    split <;> first
      | exact Cslib.LTS.MTr.refl
      | exact .stepL (ProtectionLayerStep.neutral _ _ (by trivial)) .refl }

lemma device_required_events_follow_layers {S A : Type} (binding : DeviceExecutionBinding S A)
    {before after : S} {action : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration (binding.state before) action (binding.state after)) :
    (protectionLayerSystem ⟨(binding.state before).frame.originDomain, (binding.state before).frame.payload⟩).MTr
      (binding.LayerIds (binding.state before).frame.body) (binding.RequiredEvents before action after)
      (binding.LayerIds (binding.state after).frame.body) := by
  apply (Cslib.LTS.MTr.append_iff _).mpr
  refine ⟨_, device_source_events_follow_layers binding before, ?_⟩
  have names : ∀ body, (binding.withProjection (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
      (fun operation : MultiProtocolForwarding.Action => some operation)).LayerIds body = binding.LayerIds body :=
    layer_ids_with_tunnel_names binding _ _
  dsimp only [DeviceExecutionBinding.withProjection] at names
  simpa only [DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq, names]
    using device_operation_events_follow_layers binding step

lemma required_events_with_tunnel_names {S A : Type} (binding : DeviceExecutionBinding S A)
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

lemma model_step_events_follow_layers {S A : Type} (model : ForwardingModel S A)
    (faithful : model.Faithful) {before after : S} {action : A}
    (step : model.system.Tr before action after) :
    (protectionLayerSystem ⟨(model.native.state before).frame.originDomain,
      (model.native.state before).frame.payload⟩).MTr
      (model.native.LayerIds (model.native.state before).frame.body) (model.events action)
      (model.native.LayerIds (model.native.state after).frame.body) := by
  apply layer_run_from_network_filter
  have checked := faithful before action after step
  cases selected : model.native.action action with
  | none =>
    rw [selected] at checked
    rw [checked.2, ← checked.1]
    exact .refl
  | some operation =>
    rw [selected] at checked
    rw [checked.2]
    exact device_required_events_follow_layers model.native checked.1.1

lemma forwarding_events_follow_layers {S A : Type} (model : ForwardingModel S A)
    (faithful : model.Faithful) {before after : S} {actions : List A}
    (run : model.system.MTr before actions after) :
    (protectionLayerSystem ⟨(model.native.state before).frame.originDomain,
      (model.native.state before).frame.payload⟩).MTr
      (model.native.LayerIds (model.native.state before).frame.body) (actions.flatMap model.events)
      (model.native.LayerIds (model.native.state after).frame.body) := by
  induction run with
  | refl => exact .refl
  | @stepL first operation next rest last step tail ih =>
    have identity := model.preserves_payload_identity faithful (Cslib.LTS.MTr.stepL step .refl)
    rw [identity.1, identity.2] at ih
    exact (Cslib.LTS.MTr.append_iff _).mpr
      ⟨_, model_step_events_follow_layers model faithful step, ih⟩

lemma setup_history_events_preserve_layers (history : ObservedHistory) (valid : history.Valid)
    (payload : PayloadId) (layers : List String) :
    (protectionLayerSystem payload).MTr layers history.Events layers := by
  apply neutral_events_preserve_layers
  intro event member
  obtain ⟨record, stored, same⟩ := List.mem_map.mp member
  have setup := (valid.2.1 record stored).2.2.2.2
  rw [← same]
  rcases record with ⟨source, observer, localPosition, component, position, epoch, session, recorded⟩
  cases recorded <;> simp_all [HistoricalEvent.SetupOnly, ProtectionLayerNeutral]

lemma initial_source_has_no_layers {S A : Type} (model : ForwardingModel S A) (d : Deployment)
    (source : model.SourceCoverage d) {start : S} (initial : model.initial start) :
    model.native.LayerIds (model.native.state start).frame.body = [] := by
  have plain := (source.2.2.2.1 start initial).1.2.1
  rcases plain with ⟨header, same⟩ | ⟨header, same⟩ <;>
    simp only [same, DeviceExecutionBinding.LayerIds]

lemma deployment_events_follow_layers {S A : Type} (model : ForwardingModel S A) (d : Deployment)
    (covered : model.CoversDeployment d) {start finish : S} {actions : List A}
    (initial : model.initial start) (run : model.system.MTr start actions finish) :
    (protectionLayerSystem ⟨(model.native.state start).frame.originDomain,
      (model.native.state start).frame.payload⟩).MTr [] (model.TraceEvents actions)
      (model.native.LayerIds (model.native.state finish).frame.body) := by
  have following := forwarding_events_follow_layers model covered.2.1 run
  rw [initial_source_has_no_layers model d covered.2.2.2.1 initial] at following
  exact (Cslib.LTS.MTr.append_iff _).mpr
    ⟨[], setup_history_events_preserve_layers model.history covered.2.2.2.2.1 _ [], following⟩

end TDN.Requirements.Msc
