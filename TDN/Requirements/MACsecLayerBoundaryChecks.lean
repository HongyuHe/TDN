import TDN.Requirements.LayerOutboundEventChecks
import TDN.Requirements.MACsecInboundLocalGate

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

structure MACsecLayerBoundaryChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) : Prop where
  wire : MACsecWireChecks binding.configuration
  initial : ∀ state, binding.SourceInitial d state → MACsecOutputProtected binding.configuration state
  inputs : ∀ first last, binding.configuration.physicalLink first last →
    ∀ interface ∈ d.interfaces, interface.id = binding.ifaceName last → d.IsLayer interface.device layer →
      interface.zone ≠ InternalZone layer
  outputs : ∀ first last, binding.configuration.physicalLink first last →
    ∀ interface ∈ d.interfaces, interface.id = binding.ifaceName first → d.IsLayer interface.device layer →
      interface.zone ≠ InternalZone layer ∧
      ∃ mac ∈ binding.configuration.macIfaces, first = mac.physicalIface ∧
        ∀ association, mac.transmitAssociation = some association →
        ∃ tunnel ∈ d.tunnels, tunnel.layer = layer ∧ tunnel.sender = interface.device ∧
          tunnel.id = binding.macsecTunnel association

lemma source_events_have_boundary_shape {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (genuineControl : PayloadId → Prop) (before : S) :
    ∀ event ∈ binding.SourceEvents before, LayerOutboundEventShape d genuineControl layer event := by
  dsimp only [DeviceExecutionBinding.SourceEvents]
  split
  · split
    · split
      · intro event member
        simp only [List.mem_cons, List.not_mem_nil, or_false] at member
        rcases member with rfl | rfl
        · trivial
        · intro _ interface member name component inside tunnel stored selected
          simp
      · simp
    · simp
  · simp

lemma non_network_event_has_boundary_shape (d : Deployment) (layer : Layer)
    (genuineControl : PayloadId → Prop) (event : NetworkEvent)
    (other : event.NetworkOperation = false) : LayerOutboundEventShape d genuineControl layer event := by
  cases event <;> simp_all [NetworkEvent.NetworkOperation, LayerOutboundEventShape]

lemma nontransmit_operation_events_have_boundary_shape {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (genuineControl : PayloadId → Prop)
    (before after : S) (operation : MultiProtocolForwarding.Action) (other : operation ≠ .linkTransmit) :
    ∀ event ∈ binding.OperationEvents before operation after, LayerOutboundEventShape d genuineControl layer event := by
  cases operation <;> simp_all only [DeviceExecutionBinding.OperationEvents]
  all_goals repeat' first
    | split
    | simp_all [LayerOutboundEventShape]

lemma macsec_operation_events_have_boundary_shape {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (genuineControl : PayloadId → Prop)
    (checks : MACsecLayerBoundaryChecks binding d layer)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (safe : MACsecOutputProtected binding.configuration before) :
    ∀ event ∈ (binding.withProjection id (fun action => some action)).OperationEvents before operation after,
      LayerOutboundEventShape d genuineControl layer event := by
  by_cases transmitting : operation = .linkTransmit
  · subst operation
    cases step with
    | linkTransmit next ready linked =>
      intro event member
      simp only [DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq,
        List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl | rfl | rfl
      · trivial
      · intro _ interface stored name component
        obtain ⟨outside, mac, configured, physical, tunnels⟩ := checks.outputs _ _ linked interface stored name component
        refine ⟨fun inside => False.elim (outside inside), fun _ => ?_⟩
        obtain ⟨association, body, installed, framed⟩ := safe.2 ready mac configured physical
        obtain ⟨tunnel, present, selectedLayer, sender, identity⟩ := tunnels association installed
        refine ⟨tunnel, present, selectedLayer, sender, ?_⟩
        rw [framed, DeviceExecutionBinding.LayerIds, identity]
        exact List.mem_cons_self
      · intro _ interface stored name component inside
        exact False.elim (checks.inputs _ _ linked interface stored name component inside)
      · trivial
  · exact nontransmit_operation_events_have_boundary_shape _ d layer genuineControl before after operation transmitting

def macsecLayerOutboundChecks {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (layer : Layer) (covered : model.CoversDeployment d)
    (checks : MACsecLayerBoundaryChecks model.native d layer) : LayerOutboundLocalChecks d model layer := by
  refine ⟨fun state => MACsecOutputProtected model.native.configuration (model.native.state state),
    ?_, ?_, ?_⟩
  · intro state initial
    exact checks.initial _ (covered.2.2.2.1.2.2.2.1 state initial).1
  · intro before action after step safe
    have faithful := covered.2.1 before action after step
    cases selected : model.native.action action with
    | none => rw [selected] at faithful; rw [← faithful.1]; exact safe
    | some operation =>
      rw [selected] at faithful
      exact step_preserves_macsec_output_protection checks.wire.output faithful.1.1 safe
  · intro before action after step safe event member
    by_cases network : event.NetworkOperation = true
    · have recorded := List.mem_filter.mpr ⟨member, network⟩
      have faithful := covered.2.1 before action after step
      cases selected : model.native.action action with
      | none => rw [selected] at faithful; rw [faithful.2] at recorded; simp at recorded
      | some operation =>
        rw [selected] at faithful
        rw [faithful.2, DeviceExecutionBinding.RequiredEvents] at recorded
        rcases List.mem_append.mp recorded with source | operationEvent
        · exact source_events_have_boundary_shape _ _ _ _ _ event source
        · have localEvents := macsec_operation_events_have_boundary_shape model.native d layer model.GenuineControl
            checks faithful.1.1 safe
          have projected :
              (model.native.withProjection id (fun action => some action)).OperationEvents
                (model.native.state before) operation (model.native.state after) =
              model.native.OperationEvents before operation after := by
            have names : ∀ body, (model.native.withProjection
                (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
                (fun action : MultiProtocolForwarding.Action => some action)).LayerIds body =
                model.native.LayerIds body := layer_ids_with_tunnel_names model.native _ _
            dsimp only [DeviceExecutionBinding.withProjection] at names
            simp only [DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq, names]
          rw [projected] at localEvents
          exact localEvents event operationEvent
    · exact non_network_event_has_boundary_shape d layer model.GenuineControl event (by cases value : event.NetworkOperation <;> simp_all)

end TDN.Requirements.Msc
