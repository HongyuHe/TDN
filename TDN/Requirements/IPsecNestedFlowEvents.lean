import TDN.Requirements.IPsecFlowPolicyChecks
import TDN.Requirements.LocalInputDestinationChecks
import TDN.Requirements.StandardDataPlaneBridge

namespace TDN.Requirements.Msc
open Compliance LayeredFrame MultiProtocolForwarding

def packetBinding {S A : Type} (binding : DeviceExecutionBinding S A) :=
  binding.withProjection (fun state : MultiProtocolForwarding.State => state)
    (fun action : MultiProtocolForwarding.Action => some action)

lemma packet_binding_layer_ids {S A : Type} (binding : DeviceExecutionBinding S A) (body : Body) :
    (packetBinding binding).LayerIds body = binding.LayerIds body := by
  induction body <;> simp_all [DeviceExecutionBinding.LayerIds, packetBinding, DeviceExecutionBinding.withProjection]

lemma packet_binding_source_events {S A : Type} (binding : DeviceExecutionBinding S A) (before : S) :
    binding.SourceEvents before = (packetBinding binding).SourceEvents (binding.state before) := by
  have layers := packet_binding_layer_ids binding (binding.state before).frame.body
  dsimp only [packetBinding, DeviceExecutionBinding.withProjection] at layers
  dsimp only [DeviceExecutionBinding.SourceEvents, packetBinding, DeviceExecutionBinding.withProjection]
  rw [layers]

lemma packet_binding_operation_events {S A : Type} (binding : DeviceExecutionBinding S A)
    (before after : S) (operation : MultiProtocolForwarding.Action) :
    binding.OperationEvents before operation after =
      (packetBinding binding).OperationEvents (binding.state before) operation (binding.state after) := by
  have first := packet_binding_layer_ids binding (binding.state before).frame.body
  have last := packet_binding_layer_ids binding (binding.state after).frame.body
  dsimp only [packetBinding, DeviceExecutionBinding.withProjection] at first last
  dsimp only [DeviceExecutionBinding.OperationEvents, packetBinding, DeviceExecutionBinding.withProjection]
  rw [first, last]

lemma packet_binding_required_events {S A : Type} (binding : DeviceExecutionBinding S A)
    (before after : S) (operation : MultiProtocolForwarding.Action) :
    binding.RequiredEvents before operation after =
      (packetBinding binding).RequiredEvents (binding.state before) operation (binding.state after) := by
  exact congrArg₂ List.append (packet_binding_source_events binding before)
    (packet_binding_operation_events binding before after operation)

structure IPsecFlowIfaceChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (selected : IPsecFlowEndpoints) (expectedEncapStack : Nat → List Nat) : Prop where
  gray : ∀ iface interface, interface ∈ d.interfaces → binding.ifaceName iface = interface.id →
    interface.zone = .gray → expectedEncapStack iface = [1]
  black : ∀ iface interface, interface ∈ d.interfaces → binding.ifaceName iface = interface.id →
    interface.zone = .black → expectedEncapStack iface = [2, 1]
  sourceNotBlack : ∀ iface network, binding.sourceEntry iface = some network →
    ∀ interface ∈ d.interfaces, binding.ifaceName iface = interface.id → interface.zone ≠ .black
  localRecipient : ∀ iface header domain,
    binding.configuration.ip.ifaceSecurityDomain iface = some domain →
    binding.configuration.ip.localAddress iface header.destination →
    selected.PlainAllowed binding.configuration.ip.owner iface (.datagram header) →
    selected.RemoteHeader (some header) → binding.domainName domain = selected.flow.destinationNetwork

lemma ipsec_flow_source_events_checked {S A T B : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (model : ForwardingModel T B) (flows : List Flow) (selected : IPsecFlowEndpoints)
    (expectedEncapStack : Nat → List Nat) (checks : IPsecFlowIfaceChecks binding d selected expectedEncapStack)
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

lemma ipsec_flow_operation_events_checked {S A T B : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (model : ForwardingModel T B) (flows : List Flow) (selected : IPsecFlowEndpoints)
    (expectedEncapStack : Nat → List Nat) (checks : IPsecFlowIfaceChecks binding d selected expectedEncapStack)
    (processing : HeaderProcessing) (mode : binding.configuration.headerProcessing = some processing)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (safeBefore : IPsecFlowInvariant binding selected.flow selected.RemoteHeader selected.AllowedStamp
      (selected.PlainAllowed binding.configuration.ip.owner) expectedEncapStack before)
    (safeAfter : IPsecFlowInvariant binding selected.flow selected.RemoteHeader selected.AllowedStamp
      (selected.PlainAllowed binding.configuration.ip.owner) expectedEncapStack after)
    (localInput : LocalInputDestinationChecked binding.configuration before)
    (member : selected.flow ∈ flows) :
    ∀ event ∈ (packetBinding binding).OperationEvents before operation after,
      NestedFlowEventChecks d model flows (fun _ => selected.flow)
        (fun _ => selected.RemoteHeader before.frame.body.originalHeader) event := by
  have names : (packetBinding binding).LayerIds before.frame.body =
      before.frame.body.protectionLayers.map (flowTunnelName selected.flow) := by
    rw [packet_binding_layer_ids]
    exact flow_ipsec_body_has_selected_tunnel_names binding selected.flow selected.RemoteHeader
      selected.AllowedStamp before.frame.body safeBefore.2.1
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
        have shape := layout.trans (checks.gray before.iface interface listed name.symm gray)
        exact ⟨member, by simpa [shape, flowTunnelName] using names⟩
      · intro black
        have shape := layout.trans (checks.black before.iface interface listed name.symm black)
        refine ⟨member, ?_, ?_⟩
        · simpa [shape, flowTunnelName] using names
        · exact flow_ipsec_inner_layer_has_remote_destination binding selected.flow selected.RemoteHeader
            selected.AllowedStamp before.frame.body safeBefore.2.1 (by simp [shape])
    · intro classified interface listed relevant name black
      have shape := nextLayout.trans (checks.black next interface listed name.symm black)
      refine ⟨member, ?_, ?_⟩
      · simpa [shape, flowTunnelName] using names
      · exact flow_ipsec_inner_layer_has_remote_destination binding selected.flow selected.RemoteHeader
          selected.AllowedStamp before.frame.body safeBefore.2.1 (by simp [shape])
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
    obtain ⟨nominal, originalHeader, identity⟩ := plain_ipsec_flow_visible_header binding selected processing mode
      before.frame actual safeBefore.1.1 visible safeBefore.2.1 empty
    have same : nominal = header := by simpa only [body, Body.originalHeader, Option.some.injEq] using originalHeader.symm
    subst nominal
    have address := localInput stage actual visible
    have actualRemote : selected.RemoteHeader (some header) := by simpa only [originalHeader] using remote
    refine ⟨member, ?_, ?_⟩
    · apply checks.localRecipient before.iface header domain recipient
      · simpa only [identity.destination] using address
      · simpa only [body] using safeBefore.2.2 empty
      · exact actualRemote
    · simp only [body, DeviceExecutionBinding.LayerIds]
  case deliverEthernet header domain stage body recipient =>
    intro event stored
    dsimp only [packetBinding, DeviceExecutionBinding.withProjection, DeviceExecutionBinding.OperationEvents] at stored
    simp only [recipient, List.mem_singleton] at stored
    subst event
    intro remote
    simp only [body, Body.originalHeader, IPsecFlowEndpoints.RemoteHeader] at remote
  all_goals
    intro event stored
    dsimp only [packetBinding, DeviceExecutionBinding.withProjection, DeviceExecutionBinding.OperationEvents] at stored
    all_goals try split at stored
    all_goals simp only [List.mem_cons, List.not_mem_nil, or_false] at stored
    all_goals rcases stored with rfl | rfl | rfl <;> trivial

end TDN.Requirements.Msc
