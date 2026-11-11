import TDN.Deployments.NestedProtection_BaselineIfaceChecks
import TDN.Requirements.NestedLayerProtection
import TDN.Models.InnerHeaderPreservation

namespace TDN.Deployments.NestedProtection_Baseline
open Compliance Requirements Requirements.Msc MtuSizing_Records LayeredFrame MultiProtocolForwarding StandardDataPlaneBridge

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma source_request_context (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) (request : PacketSource.Request)
    (allowed : (binding (deviceBinding primitive) records.inventory.ifaces).SourceRequestAllowed (authenticationDeployment primitive) request) :
    contextFor request.originDomain ∈ contexts ∧
    (contextFor request.originDomain).originDomain = request.originDomain ∧
    (contextFor request.originDomain).flow.sourceNetwork = OuterTunnelNoBypass_Baseline.redNetwork request.originDomain ∧
    (contextFor request.originDomain).SourceSide (capturedConfiguration.ip.owner request.iface) := by
  have entry := allowed.2.2
  change sourceEntry entries request.iface = some (OuterTunnelNoBypass_Baseline.redNetwork request.originDomain) ∧ _ at entry
  obtain ⟨record, member, same, network⟩ := source_entry_is_recorded entries request.iface _ entry.1
  have unique : ∀ first ∈ entries, ∀ second ∈ entries,
      first.network = second.network → first.originDomain = second.originDomain := by decide
  have named : ∀ record ∈ entries, record.network ≠ "" := by decide
  have domain : request.originDomain = record.originDomain := by
    unfold OuterTunnelNoBypass_Baseline.redNetwork at network
    cases found : entries.find? (fun candidate => candidate.originDomain == request.originDomain) with
    | none =>
      have empty : record.network = "" := by simpa only [found, Option.map_none, Option.getD_none] using network
      exact False.elim (named record member empty)
    | some other =>
      have otherMember := List.mem_of_find?_eq_some found
      have matching : other.originDomain = request.originDomain := beq_iff_eq.mp
        (List.find?_some (p := fun candidate : SourceEntry => candidate.originDomain == request.originDomain) found)
      have sameNetwork : record.network = other.network := by simpa only [found, Option.map_some, Option.getD_some] using network
      exact matching.symm.trans (unique other otherMember record member sameNetwork.symm)
  have checked := recorded_source_contexts record member
  rw [domain]
  refine ⟨checked.1, checked.2.2.1, ?_, ?_⟩
  · exact checked.2.1.trans (by simpa only [domain] using network)
  · simpa only [same] using checked.2.2.2

def flowAt (state : StandardDataPlaneBridge.State records.inventory.ifaces) (_ : PayloadId) : Flow :=
  (contextFor state.native.frame.originDomain).flow

def RemoteDestination (state : StandardDataPlaneBridge.State records.inventory.ifaces) (_ : PayloadId) : Prop :=
  (contextFor state.native.frame.originDomain).RemoteHeader state.native.frame.body.originalHeader

def ForwardingInvariant (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (state : StandardDataPlaneBridge.State records.inventory.ifaces) : Prop :=
  let selected := contextFor state.native.frame.originDomain
  selected ∈ contexts ∧ selected.originDomain = state.native.frame.originDomain ∧
  IPsecFlowInvariant (deviceBinding primitive) selected.flow selected.RemoteHeader selected.AllowedStamp
    (selected.PlainAllowed (configuration primitive).ip.owner) expectedEncapStack state.native ∧
  LocalInputDestinationChecked (configuration primitive) state.native

lemma initial_selected_flow (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (state : StandardDataPlaneBridge.State records.inventory.ifaces) (initial : (authenticationForwarding primitive).initial state) :
    ForwardingInvariant primitive state := by
  obtain ⟨request, datagrams, datagram, source, allowed, emitted, member, same⟩ := initial.2
  have selected := source_request_context primitive request allowed
  have origin : (deviceBinding primitive).origin state.native.frame.originDomain =
      .red (OuterTunnelNoBypass_Baseline.redNetwork state.native.frame.originDomain) := rfl
  have stack := (binding (deviceBinding primitive) records.inventory.ifaces).source_initial_red_stack
    (authenticationDeployment primitive) expectedEncapStack source_encap_stacks state.native initial.1 _ origin
  have selectedMember : contextFor state.native.frame.originDomain ∈ contexts := by simpa only [same, DeviceExecutionBinding.SourceState] using selected.1
  have selectedDomain : (contextFor state.native.frame.originDomain).originDomain = state.native.frame.originDomain := by
    simpa only [same, DeviceExecutionBinding.SourceState] using selected.2.1
  refine ⟨selectedMember, selectedDomain, ⟨stack, ?_, ?_⟩, ?_⟩
  · rcases initial.1.2.1 with ⟨header, body⟩ | ⟨header, body⟩ <;> simp only [body, FlowIPsecBody]
  · intro empty
    apply Or.inl
    have owner : (configuration primitive).ip.owner = capturedConfiguration.ip.owner := rfl
    rw [owner]
    simpa only [same, DeviceExecutionBinding.SourceState] using selected.2.2.2
  · intro stage header visible
    rw [same] at stage
    change DataPlaneForwarding.DatapathStage.received = .localInput at stage
    cases stage

lemma step_preserves_forwarding_invariant (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    {before after : StandardDataPlaneBridge.State records.inventory.ifaces} {action : StandardDataPlaneBridge.Action records.inventory.ifaces}
    (safe : ForwardingInvariant primitive before)
    (step : (authenticationForwarding primitive).system.Tr before action after) :
    ForwardingInvariant primitive after := by
  have nativeStep := step.2.2.2.1
  have origin := (MultiProtocolForwarding.step_preserves_payload nativeStep).2
  change contextFor after.native.frame.originDomain ∈ contexts ∧ _
  rw [origin]
  refine ⟨safe.1, safe.2.1, ?_, ?_⟩
  · exact step_preserves_selected_flow primitive _ safe.1 nativeStep safe.2.2.1
  · exact step_preserves_local_input_destination nativeStep safe.2.2.2

lemma recorded_context_origins : ∀ selected ∈ contexts,
    OuterTunnelNoBypass_Baseline.redNetwork selected.originDomain = selected.flow.sourceNetwork := by decide

lemma flow_events_checked (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    {before after : StandardDataPlaneBridge.State records.inventory.ifaces} {action : StandardDataPlaneBridge.Action records.inventory.ifaces}
    (safe : ForwardingInvariant primitive before)
    (step : (authenticationForwarding primitive).system.Tr before action after) :
    ∀ event ∈ (authenticationForwarding primitive).events action,
      NestedFlowEventChecks (authenticationDeployment primitive) (authenticationForwarding primitive)
        flows (flowAt before) (RemoteDestination before) event := by
  obtain ⟨sameBefore, sameAfter, source, accepted⟩ := step
  subst before
  subst after
  intro event stored
  change event ∈ (binding (deviceBinding primitive) records.inventory.ifaces).RequiredEvents
    action.before action.operation action.after at stored
  rw [packet_binding_required_events] at stored
  change event ∈ (packetBinding (deviceBinding primitive)).SourceEvents action.before.native ++
    (packetBinding (deviceBinding primitive)).OperationEvents action.before.native action.operation action.after.native at stored
  let selected := contextFor action.before.native.frame.originDomain
  have selectedMember : selected ∈ contexts := safe.1
  have flowMember : selected.flow ∈ flows := List.mem_map.mpr ⟨selected, selectedMember, rfl⟩
  have origin : (deviceBinding primitive).origin action.before.native.frame.originDomain = .red selected.flow.sourceNetwork := by
    change PayloadOrigin.red (OuterTunnelNoBypass_Baseline.redNetwork action.before.native.frame.originDomain) = _
    rw [← safe.2.1, recorded_context_origins selected selectedMember]
  rcases List.mem_append.mp stored with sourceEvent | forwardingEvent
  · have classified : (authenticationForwarding primitive).ProtectedPayload (authenticationDeployment primitive)
        ⟨action.before.native.frame.originDomain, action.before.native.frame.payload⟩ := by
      obtain ⟨network, member, name⟩ := recorded_context_networks selected selectedMember
      exact ⟨network, member, origin.trans (congrArg PayloadOrigin.red name)⟩
    exact ipsec_flow_source_events_checked (deviceBinding primitive) (authenticationDeployment primitive)
      (authenticationForwarding primitive) flows selected expectedEncapStack (flow_iface_checks primitive selected selectedMember)
      action.before.native flowMember origin classified event sourceEvent
  · exact ipsec_flow_operation_events_checked (deviceBinding primitive) (authenticationDeployment primitive)
      (authenticationForwarding primitive) flows selected expectedEncapStack (flow_iface_checks primitive selected selectedMember)
      ⟨fun _ => 64, fun _ => 64⟩ rfl accepted.1 safe.2.2.1
      (step_preserves_selected_flow primitive selected selectedMember accepted.1 safe.2.2.1)
      safe.2.2.2 flowMember event forwardingEvent

lemma nested_flow_checks (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    NestedFlowChecks (authenticationDeployment primitive) (authenticationForwarding primitive) flows
      flowAt RemoteDestination (ForwardingInvariant primitive) := by
  refine ⟨initial_selected_flow primitive, ?_, ?_, ?_, ?_⟩
  · intro before action after safe step
    exact step_preserves_forwarding_invariant primitive safe step
  · intro before action after safe step
    have origin := (MultiProtocolForwarding.step_preserves_payload step.2.2.2.1).2
    funext payload
    simp only [flowAt, origin]
  · intro before action after safe step
    have origin := (MultiProtocolForwarding.step_preserves_payload step.2.2.2.1).2
    have header := MultiProtocolForwarding.step_preserves_original_header step.2.2.2.1
    funext payload
    simp only [RemoteDestination, origin, header]
  · intro before action after safe step
    exact flow_events_checked primitive safe step

theorem snapshot_RG007_ipsec_nested_layer_protection (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (independentKeys : String → String → Prop) (independent : IndependentLayerKeys independentKeys) :
    msc_nested_layer_protection (authenticationDeployment primitive) (authenticationForwarding primitive) flows
      (fun start _ _ payload => flowAt start payload) independentKeys :=
  nested_layer_protection_from_local_checks (authenticationDeployment primitive) (authenticationForwarding primitive)
    flows flowAt RemoteDestination (ForwardingInvariant primitive) independentKeys
    (authentication_deployment_covered primitive) (authentication_architecture_services primitive)
    (flows_valid primitive independentKeys independent) (nested_flow_checks primitive)

end TDN.Deployments.NestedProtection_Baseline
