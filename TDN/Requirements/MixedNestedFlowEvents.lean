import TDN.Requirements.MixedFlowPolicyChecks
import TDN.Requirements.IPsecNestedFlowEvents

namespace TDN.Requirements.Msc
open Compliance LayeredFrame MultiProtocolForwarding

structure MixedFlowIfaceChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (selected : MixedFlowEndpoints) (expectedEncapStack : Nat → List Nat) : Prop where
  gray : ∀ iface interface, interface ∈ d.interfaces → binding.ifaceName iface = interface.id →
    (∃ peer, binding.configuration.physicalLink iface peer ∨ binding.configuration.physicalLink peer iface) →
    interface.zone = .gray → expectedEncapStack iface = [1]
  black : ∀ iface interface, interface ∈ d.interfaces → binding.ifaceName iface = interface.id →
    (∃ peer, binding.configuration.physicalLink iface peer ∨ binding.configuration.physicalLink peer iface) →
    interface.zone = .black → expectedEncapStack iface = [2, 1]
  sourceNotBlack : ∀ iface network, binding.sourceEntry iface = some network →
    ∀ interface ∈ d.interfaces, binding.ifaceName iface = interface.id → interface.zone ≠ .black
  localRecipient : ∀ iface header domain,
    binding.configuration.ip.ifaceSecurityDomain iface = some domain →
    binding.configuration.ip.localAddress iface header.destination →
    selected.PlainAllowed binding.configuration.ip.owner iface (.datagram header) →
    selected.RemoteHeader (some header) → binding.domainName domain = selected.flow.destinationNetwork

lemma mixed_flow_source_events_checked {S A T B : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (model : ForwardingModel T B) (flows : List Flow) (selected : MixedFlowEndpoints)
    (expectedEncapStack : Nat → List Nat) (checks : MixedFlowIfaceChecks binding d selected expectedEncapStack)
    (state : MultiProtocolForwarding.State) (member : selected.flow ∈ flows)
    (origin : binding.origin state.frame.originDomain = .red selected.flow.sourceNetwork)
    (classified : model.ProtectedPayload d ⟨state.frame.originDomain, state.frame.payload⟩) :
    ∀ event ∈ (packetBinding binding).SourceEvents state,
      NestedFlowEventChecks d model flows (fun _ => selected.flow)
        (fun _ => selected.RemoteHeader state.frame.body.originalHeader) event := by
  intro event stored
  dsimp only [DeviceExecutionBinding.SourceEvents] at stored
  change event ∈ (if state.initialEntry = true then
    match binding.origin state.frame.originDomain with
    | .red network =>
      if binding.sourceEntry state.iface = some network ∧ (packetBinding binding).LayerIds state.frame.body = []
      then [.inject ⟨state.frame.originDomain, state.frame.payload⟩ network,
        .receive ⟨state.frame.originDomain, state.frame.payload⟩ (binding.ifaceName state.iface) [] .protectedData]
      else []
    | _ => []
    else []) at stored
  rw [packet_binding_layer_ids] at stored
  split at stored
  next entry =>
    simp only [origin] at stored
    split at stored
    next source =>
      rcases List.mem_cons.mp stored with injected | received
      · subst event
        exact ⟨member, rfl, classified⟩
      · have same := List.mem_singleton.mp received
        subst event
        intro protectedPayload interface listed relevant name black
        exact False.elim (checks.sourceNotBlack state.iface selected.flow.sourceNetwork source.1 interface listed name.symm black)
    next => exact False.elim (List.not_mem_nil stored)
  next => exact False.elim (List.not_mem_nil stored)

lemma mixed_flow_operation_events_checked {S A T B : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (model : ForwardingModel T B) (flows : List Flow) (selected : MixedFlowEndpoints)
    (expectedEncapStack : Nat → List Nat) (checks : MixedFlowIfaceChecks binding d selected expectedEncapStack)
    (processing : HeaderProcessing) (mode : binding.configuration.headerProcessing = some processing)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (safeBefore : MixedFlowInvariant binding selected.flow selected.RemoteHeader (· = selected.innerStamp)
      (· = selected.outerAssociation) (selected.PlainAllowed binding.configuration.ip.owner) expectedEncapStack
      selected.destinationLogicalIface before)
    (safeAfter : MixedFlowInvariant binding selected.flow selected.RemoteHeader (· = selected.innerStamp)
      (· = selected.outerAssociation) (selected.PlainAllowed binding.configuration.ip.owner) expectedEncapStack
      selected.destinationLogicalIface after)
    (localInput : LocalInputDestinationChecked binding.configuration before)
    (member : selected.flow ∈ flows) :
    ∀ event ∈ (packetBinding binding).OperationEvents before operation after,
      NestedFlowEventChecks d model flows (fun _ => selected.flow)
        (fun _ => selected.RemoteHeader before.frame.body.originalHeader) event := by
  have names : (packetBinding binding).LayerIds before.frame.body =
      before.frame.body.protectionLayers.map (flowTunnelName selected.flow) := by
    rw [packet_binding_layer_ids]
    exact flow_mixed_body_has_selected_tunnel_names binding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation) before.frame.body safeBefore.2.1
  dsimp only [packetBinding, DeviceExecutionBinding.withProjection] at names
  cases step
  case linkTransmit next stage linked =>
    have layout : before.frame.body.protectionLayers = expectedEncapStack before.iface := by
      simpa only [stage] using safeBefore.1.2.2
    have nextLayout : before.frame.body.protectionLayers = expectedEncapStack next := by
      simpa only [HeaderedStackInvariant] using safeAfter.1.2.2
    intro event stored
    dsimp only [packetBinding, DeviceExecutionBinding.withProjection, DeviceExecutionBinding.OperationEvents] at stored
    simp only [List.mem_cons, List.not_mem_nil, or_false] at stored
    rcases stored with rfl | rfl | rfl | rfl
    · trivial
    · intro classified interface listed relevant name
      constructor
      · intro gray
        have shape := layout.trans (checks.gray before.iface interface listed name.symm ⟨next, Or.inl linked⟩ gray)
        exact ⟨member, by simpa [shape, flowTunnelName] using names⟩
      · intro black
        have shape := layout.trans (checks.black before.iface interface listed name.symm ⟨next, Or.inl linked⟩ black)
        refine ⟨member, ?_, ?_⟩
        · simpa [shape, flowTunnelName] using names
        · exact flow_mixed_inner_layer_has_remote_destination binding selected.flow selected.RemoteHeader
            (· = selected.innerStamp) (· = selected.outerAssociation) before.frame.body safeBefore.2.1 (by simp [shape])
    · intro classified interface listed relevant name black
      have shape := nextLayout.trans (checks.black next interface listed name.symm ⟨before.iface, Or.inr linked⟩ black)
      refine ⟨member, ?_, ?_⟩
      · simpa [shape, flowTunnelName] using names
      · exact flow_mixed_inner_layer_has_remote_destination binding selected.flow selected.RemoteHeader
          (· = selected.innerStamp) (· = selected.outerAssociation) before.frame.body safeBefore.2.1 (by simp [shape])
    · trivial
  case deliver domain stage body recipient =>
    rename_i header
    intro event stored
    dsimp only [packetBinding, DeviceExecutionBinding.withProjection, DeviceExecutionBinding.OperationEvents] at stored
    simp only [recipient, List.mem_singleton] at stored
    subst event
    intro remote
    have empty : before.frame.body.protectionLayers = [] := by simp only [body, Body.protectionLayers]
    have inputShape := safeBefore.1.2.2
    rw [stage] at inputShape
    obtain ⟨actual, actualVisible, _⟩ := inputShape
    have visible : binding.configuration.visibleHeader before.frame = some actual := by
      simpa only [Config.visibleHeader, mode] using actualVisible
    obtain ⟨nominal, originalHeader, identity⟩ := plain_mixed_flow_visible_header binding selected processing mode
      before.frame actual safeBefore.1.1 visible safeBefore.2.1 empty
    have same : nominal = header := by simpa only [body, Body.originalHeader, Option.some.injEq] using originalHeader.symm
    subst nominal
    have address := localInput stage actual visible
    have actualRemote : selected.RemoteHeader (some header) := by simpa only [originalHeader] using remote
    refine ⟨member, ?_, ?_⟩
    · apply checks.localRecipient before.iface header domain recipient
      · simpa only [identity.destination] using address
      · simpa only [body] using safeBefore.2.2.1 empty
      · exact actualRemote
    · simp only [body, DeviceExecutionBinding.LayerIds]
  case deliverEthernet header domain stage body recipient =>
    intro event stored
    dsimp only [packetBinding, DeviceExecutionBinding.withProjection, DeviceExecutionBinding.OperationEvents] at stored
    simp only [recipient, List.mem_singleton] at stored
    subst event
    intro remote
    simp only [body, Body.originalHeader, MixedFlowEndpoints.RemoteHeader] at remote
  all_goals
    intro event stored
    dsimp only [packetBinding, DeviceExecutionBinding.withProjection, DeviceExecutionBinding.OperationEvents] at stored
    all_goals try split at stored
    all_goals simp only [List.mem_cons, List.not_mem_nil, or_false] at stored
    all_goals rcases stored with rfl | rfl | rfl <;> trivial

end TDN.Requirements.Msc
