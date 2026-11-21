import TDN.Models.MultiProtocolEncryptionEvents
import TDN.Requirements.InnerOuterTunnelCompositionSpec

namespace TDN.Requirements
open MultiProtocolForwarding LayeredFrame

def MultiProtocolRedOrigin (sources : List Nat) (state : MultiProtocolForwarding.TunnelForwardingState) : Prop :=
  state.iface ∈ sources ∧ state.enteredIface = state.iface ∧ state.authenticated = [] ∧
  ((state.datapathStage = .localOutput ∧ ∃ header, state.frame.body = .datagram header) ∨
   (state.datapathStage = .egressReady ∧ ∃ header, state.frame.body = .ethernet header))

lemma multi_protocol_red_initial_invariant (c : MultiProtocolForwarding.TunnelForwardingModel) (expectedEncapStack : Nat → List Nat)
    (sources : List Nat)
    (checked : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.ip.canOriginateTraffic iface)
    {state : MultiProtocolForwarding.TunnelForwardingState} (origin : MultiProtocolRedOrigin sources state) :
    MultiProtocolForwarding.EncapStackConsistent c expectedEncapStack state := by
  obtain ⟨member, entered, empty, source⟩ := origin
  obtain ⟨stack, admitted⟩ := checked state.iface member
  rcases source with ⟨datapathStage, header, plain⟩ | ⟨datapathStage, header, plain⟩
  · refine ⟨?_, ?_⟩
    · simp [CarrierBodies, plain]
    · simp only [datapathStage]
      refine ⟨header, by simp [plain, Body.visibleHeader], ⟨?_, Or.inl empty, ?_⟩,
        Or.inl ?_, empty, entered⟩
      · simp [plain, Body.protectionLayers, DataPlaneForwarding.encapStackAfterIngress, empty, entered, stack]
      · simp [entered]
      · simpa [entered] using admitted
  · exact ⟨by simp [CarrierBodies, plain], by simp [datapathStage, plain, Body.protectionLayers, stack]⟩

lemma multi_protocol_red_origin_has_no_layers (sources : List Nat)
    {state : MultiProtocolForwarding.TunnelForwardingState} (origin : MultiProtocolRedOrigin sources state) :
    state.frame.body.protectionLayers = [] := by
  rcases origin.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [plain, Body.protectionLayers]

theorem multi_protocol_black_transmission_has_ordered_encryptions
    (c : MultiProtocolForwarding.TunnelForwardingModel) (expectedEncapStack : Nat → List Nat)
    (sources blackIfaces : List Nat)
    (conditions : MultiProtocolForwarding.LocalConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.ip.canOriginateTraffic iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    (placement : ∀ iface, (expectedEncapStack iface).head? = some 2 → expectedEncapStack iface = [2, 1])
    {start finish : MultiProtocolForwarding.TunnelForwardingState} {actions : List MultiProtocolForwarding.TunnelForwardingAction}
    (source : MultiProtocolRedOrigin sources start) (run : (lts c).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    MultiProtocolForwarding.OrderedEncryptions c 1 2 start actions finish := by
  have initial := multi_protocol_red_initial_invariant c expectedEncapStack sources sourceCheck source
  have preserved := all_traces_preserve_stack c expectedEncapStack conditions run initial
  have layers : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
    simpa only [ready] using preserved.2
  apply MultiProtocolForwarding.nested_stack_requires_ordered_encryptions c expectedEncapStack conditions 1 2
    placement run initial (multi_protocol_red_origin_has_no_layers sources source)
  simp [layers, blackCheck finish.iface black]

end TDN.Requirements
