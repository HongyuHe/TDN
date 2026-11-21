import TDN.Deployments.NestedProtection_HybridIpsecMacsecIfaceChecks
import TDN.Deployments.NestedProtection_HybridIpsecMacsecWireChecks
import TDN.Deployments.NestedProtection_HybridIpsecMacsecArchitecture
import TDN.Deployments.NestedProtection_HybridIpsecMacsecBridgeChecks
import TDN.Requirements.NestedLayerProtection
import TDN.Models.InnerHeaderPreservation

namespace TDN.Deployments.NestedProtection_HybridIpsecMacsec
open Compliance Requirements Requirements.Msc MtuSizing_Records LayeredFrame MultiProtocolForwarding StandardDataPlaneBridge

set_option maxRecDepth 1000000

lemma source_request_context (request : PacketSource.Request)
    (allowed : (binding (deviceBinding) ifaces).SourceRequestAllowed (deployment) request) :
    contextFor request.originDomain ∈ contexts ∧
    (contextFor request.originDomain).originDomain = request.originDomain ∧
    (contextFor request.originDomain).flow.sourceNetwork = records.redNetwork request.originDomain ∧
    (contextFor request.originDomain).SourceSide (configuration.ip.owner request.iface) := by
  have entry := allowed.2.2
  change sourceEntry records.entries request.iface = some (records.redNetwork request.originDomain) ∧ _ at entry
  obtain ⟨record, member, same, network⟩ := source_entry_is_recorded records.entries request.iface _ entry.1
  have unique : ∀ first ∈ records.entries, ∀ second ∈ records.entries,
      first.network = second.network → first.originDomain = second.originDomain := by native_decide
  have named : ∀ record ∈ records.entries, record.network ≠ "" := by native_decide
  have domain : request.originDomain = record.originDomain := by
    unfold Records.redNetwork at network
    cases found : records.entries.find? (fun candidate => candidate.originDomain == request.originDomain) with
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

def flowAt (state : StandardDataPlaneBridge.State ifaces) (_ : PayloadId) : Flow :=
  (contextFor state.deviceState.frame.originDomain).flow

def RemoteDestination (state : StandardDataPlaneBridge.State ifaces) (_ : PayloadId) : Prop :=
  (contextFor state.deviceState.frame.originDomain).RemoteHeader state.deviceState.frame.body.originalHeader

def ForwardingInvariant     (state : StandardDataPlaneBridge.State ifaces) : Prop :=
  let selected := contextFor state.deviceState.frame.originDomain
  selected ∈ contexts ∧ selected.originDomain = state.deviceState.frame.originDomain ∧
  HybridIpsecMacsecFlowInvariant deviceBinding selected.flow selected.RemoteHeader (· = selected.innerStamp) (· = selected.outerAssociation)
    (selected.PlainAllowed configuration.ip.owner) expectedEncapStack selected.destinationLogicalIface state.deviceState ∧
  LocalInputDestinationChecked configuration state.deviceState ∧ LinkPathMACsecFramed configuration state.deviceState

lemma initial_selected_flow     (state : StandardDataPlaneBridge.State ifaces) (initial : (forwarding).initial state) :
    ForwardingInvariant state := by
  obtain ⟨request, datagrams, datagram, source, allowed, emitted, member, same⟩ := initial.2
  have selected := source_request_context request allowed
  have origin : (deviceBinding).origin state.deviceState.frame.originDomain =
      .red (records.redNetwork state.deviceState.frame.originDomain) := rfl
  have stack := (binding (deviceBinding) ifaces).source_initial_red_stack
    (deployment) expectedEncapStack source_encap_stacks state.deviceState initial.1 _ origin
  have selectedMember : contextFor state.deviceState.frame.originDomain ∈ contexts := by simpa only [same, DeviceExecutionBinding.SourceState] using selected.1
  have selectedDomain : (contextFor state.deviceState.frame.originDomain).originDomain = state.deviceState.frame.originDomain := by
    simpa only [same, DeviceExecutionBinding.SourceState] using selected.2.1
  refine ⟨selectedMember, selectedDomain, ⟨stack, ?_, ?_, ?_⟩, ?_, ?_⟩
  · rcases initial.1.2.1 with ⟨header, body⟩ | ⟨header, body⟩ <;> simp only [body, FlowMixedBody]
  · intro empty
    apply Or.inl
    simpa only [same, DeviceExecutionBinding.SourceState] using selected.2.2.2
  · have phase := initial.1.2.2.2
    change state.deviceState.datapathStage = .received ∧ _ at phase
    simp [InnerMACsecEgressGuard, phase.1]
  · intro stage header visible
    rw [same] at stage
    change DataPlaneForwarding.DatapathStage.received = .localInput at stage
    cases stage
  · intro path
    have entry := allowed.2.2
    obtain ⟨record, stored, sourceIface, _⟩ := source_entry_is_recorded records.entries request.iface _ entry.1
    have atSource : state.deviceState.iface = record.iface := by simpa only [same, DeviceExecutionBinding.SourceState] using sourceIface.symm
    rw [atSource] at path
    exact False.elim (source_entries_avoid_link_path record stored (link_path_is_recorded record.iface path))

lemma step_preserves_forwarding_invariant     {before after : StandardDataPlaneBridge.State ifaces} {action : StandardDataPlaneBridge.Action ifaces}
    (safe : ForwardingInvariant before)
    (step : (forwarding).system.Tr before action after) :
    ForwardingInvariant after := by
  have nativeStep := step.2.2.2.1
  have origin := (MultiProtocolForwarding.step_preserves_payload nativeStep).2
  change contextFor after.deviceState.frame.originDomain ∈ contexts ∧ _
  rw [origin]
  refine ⟨safe.1, safe.2.1, ?_, ?_, ?_⟩
  · exact step_preserves_selected_flow _ safe.1 nativeStep safe.2.2.1
  · exact step_preserves_local_input_destination nativeStep safe.2.2.2.1
  · exact hybrid_ipsec_macsec_step_preserves_link_path_framing deviceBinding _ expectedEncapStack
      (flow_link_checks _ safe.1) nativeStep safe.2.2.1
      (step_preserves_selected_flow _ safe.1 nativeStep safe.2.2.1) safe.2.2.2.2

lemma recorded_context_origins : ∀ selected ∈ contexts,
    records.redNetwork selected.originDomain = selected.flow.sourceNetwork := by native_decide

lemma flow_events_checked     {before after : StandardDataPlaneBridge.State ifaces} {action : StandardDataPlaneBridge.Action ifaces}
    (safe : ForwardingInvariant before)
    (step : (forwarding).system.Tr before action after) :
    ∀ event ∈ (forwarding).events action,
      NestedFlowEventChecks (deployment) (forwarding)
        flows (flowAt before) (RemoteDestination before) event := by
  obtain ⟨sameBefore, sameAfter, source, accepted⟩ := step
  subst before
  subst after
  intro event stored
  change event ∈ (binding (deviceBinding) ifaces).RequiredEvents
    action.before action.operation action.after at stored
  rw [packet_binding_required_events] at stored
  change event ∈ (packetBinding (deviceBinding)).SourceEvents action.before.deviceState ++
    (packetBinding (deviceBinding)).OperationEvents action.before.deviceState action.operation action.after.deviceState at stored
  let selected := contextFor action.before.deviceState.frame.originDomain
  have selectedMember : selected ∈ contexts := safe.1
  have flowMember : selected.flow ∈ flows := List.mem_map.mpr ⟨selected, selectedMember, rfl⟩
  have origin : (deviceBinding).origin action.before.deviceState.frame.originDomain = .red selected.flow.sourceNetwork := by
    change PayloadOrigin.red (records.redNetwork action.before.deviceState.frame.originDomain) = _
    rw [← safe.2.1, recorded_context_origins selected selectedMember]
  rcases List.mem_append.mp stored with sourceEvent | forwardingEvent
  · have classified : (forwarding).ProtectedPayload (deployment)
        ⟨action.before.deviceState.frame.originDomain, action.before.deviceState.frame.payload⟩ := by
      obtain ⟨network, member, name⟩ := recorded_context_networks selected selectedMember
      exact ⟨network, member, origin.trans (congrArg PayloadOrigin.red name)⟩
    exact hybrid_ipsec_macsec_flow_source_events_checked (deviceBinding) (deployment)
      (forwarding) flows selected expectedEncapStack (flow_iface_checks selected selectedMember)
      action.before.deviceState flowMember origin classified event sourceEvent
  · exact hybrid_ipsec_macsec_flow_operation_events_checked (deviceBinding) (deployment)
      (forwarding) flows selected expectedEncapStack (flow_iface_checks selected selectedMember)
      ⟨fun _ => 64, fun _ => 64⟩ rfl accepted.1 safe.2.2.1
      (step_preserves_selected_flow selected selectedMember accepted.1 safe.2.2.1)
      safe.2.2.2.1 flowMember event forwardingEvent

lemma nested_flow_checks :
    NestedFlowChecks (deployment) (forwarding) flows
      flowAt RemoteDestination (ForwardingInvariant) := by
  refine ⟨initial_selected_flow, ?_, ?_, ?_, ?_⟩
  · intro before action after safe step
    exact step_preserves_forwarding_invariant safe step
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
    exact flow_events_checked safe step

end TDN.Deployments.NestedProtection_HybridIpsecMacsec
