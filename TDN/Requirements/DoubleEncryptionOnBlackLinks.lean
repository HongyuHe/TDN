import TDN.Models.TableDrivenDataPlane
import TDN.Models.TunnelEncryptionEvents
import TDN.Models.ForwardedFragments

namespace TDN.Requirements

def RedPayloadOrigin (env : DataPlaneForwarding.DataPlaneModel) (redSourceIfaces : List Nat)
    (initialState : DataPlaneForwarding.State) : Prop :=
  initialState.iface ∈ redSourceIfaces ∧ initialState.datapathStage = .localOutput ∧
  initialState.frame.enteredIface = initialState.iface ∧ initialState.frame.encapLayers = [] ∧
  initialState.frame.packet.ingress = env.interfaceName initialState.iface ∧ initialState.authenticated = []

def red_traffic_is_doubly_encrypted_on_black_links (env : DataPlaneForwarding.DataPlaneModel)
    (redSourceIfaces blackIfaces : List Nat) : Prop :=
  ∀ initialState finalState actions, RedPayloadOrigin env redSourceIfaces initialState →
    DataPlaneForwarding.ForwardsAlongTrace env initialState actions finalState → finalState.datapathStage = .egressReady →
    finalState.iface ∈ blackIfaces → finalState.frame.encapLayerIds = [2, 1]

lemma red_origin_has_initial_stack (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat)
    (sources : List Nat)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.canOriginateTraffic iface)
    {start : DataPlaneForwarding.State} (origin : RedPayloadOrigin c sources start) :
    DataPlaneForwarding.EncapStackConsistent c expectedEncapStack start := by
  obtain ⟨member, datapathStage, entry, empty, ingress, authentication⟩ := origin
  obtain ⟨stack, admitted⟩ := sourceCheck start.iface member
  simp only [DataPlaneForwarding.EncapStackConsistent, datapathStage]
  refine ⟨⟨⟨?_, ?_, Or.inl authentication, ?_⟩, ?_⟩, entry⟩
  · simp [DataPlaneForwarding.Frame.encapLayerIds, empty, DataPlaneForwarding.encapStackAfterIngress, authentication, entry, stack]
  · simpa [entry] using ingress
  · simp [entry]
  · simpa [entry] using admitted

theorem protected_red_stack_from_local_checks (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat)
    (sources blackIfaces : List Nat)
    (conditions : DataPlaneForwarding.PerHopEncapConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.canOriginateTraffic iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1]) :
    red_traffic_is_doubly_encrypted_on_black_links c sources blackIfaces := by
  intro start finish actions origin run ready black
  exact (DataPlaneForwarding.egress_packet_has_expected_encap_stack c expectedEncapStack conditions run
    (red_origin_has_initial_stack c expectedEncapStack sources sourceCheck origin) ready).trans
      (blackCheck finish.iface black)

theorem protected_black_forwarding_applies_layers_in_order
    (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat) (sources blackIfaces : List Nat)
    (conditions : DataPlaneForwarding.PerHopEncapConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.canOriginateTraffic iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    (layerShapes : ∀ iface, (expectedEncapStack iface).head? = some 2 → expectedEncapStack iface = [2, 1])
    {start finish : DataPlaneForwarding.State} {actions : List DataPlaneForwarding.Action}
    (origin : RedPayloadOrigin c sources start) (run : DataPlaneForwarding.ForwardsAlongTrace c start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    DataPlaneForwarding.OrderedEncryptions c 1 2 start actions finish := by
  have initial := red_origin_has_initial_stack c expectedEncapStack sources sourceCheck origin
  have stack := (DataPlaneForwarding.egress_packet_has_expected_encap_stack c expectedEncapStack conditions run initial ready).trans
    (blackCheck finish.iface black)
  apply DataPlaneForwarding.nested_stack_requires_ordered_encryptions c expectedEncapStack conditions 1 2
    layerShapes run initial
  · simp [DataPlaneForwarding.Frame.encapLayerIds, origin.2.2.2.1]
  · simp [stack]

theorem fragmented_black_transmission_keeps_layers {Header Byte : Type} [DecidableEq Header]
    (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat) (sources blackIfaces : List Nat)
    (encode : DataPlaneForwarding.State → Fragmentation.Datagram Header Byte)
    (conditions : DataPlaneForwarding.PerHopEncapConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.canOriginateTraffic iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State Header Byte}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : RedPayloadOrigin c sources start.logical)
    (run : (Fragmentation.segmented (DataPlaneForwarding.lts c) encode).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    finish.logical.frame.encapLayerIds = [2, 1] := by
  have preserved := Fragmentation.fragmented_forwarding_preserves_invariant
    (Fragmentation.segmented (DataPlaneForwarding.lts c) encode) (DataPlaneForwarding.lts c)
    Fragmentation.SegmentedState.logical
    (Fragmentation.segmented_projection_checked (DataPlaneForwarding.lts c) encode)
    (DataPlaneForwarding.EncapStackConsistent c expectedEncapStack)
    (fun _ _ _ step invariant => DataPlaneForwarding.hop_preserves_encap_stack conditions step invariant)
    run (red_origin_has_initial_stack c expectedEncapStack sources sourceCheck origin)
  have stack : finish.logical.frame.encapLayerIds = expectedEncapStack finish.logical.iface := by
    simpa [DataPlaneForwarding.EncapStackConsistent, ready] using preserved
  exact stack.trans (blackCheck finish.logical.iface black)

theorem every_black_fragment_has_both_layers {Byte : Type}
    (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat) (sources blackIfaces : List Nat)
    (encodedBytes : DataPlaneForwarding.Frame → List Byte)
    (conditions : DataPlaneForwarding.PerHopEncapConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.canOriginateTraffic iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    {start finish : Fragmentation.SegmentedState DataPlaneForwarding.State DataPlaneForwarding.FragmentDescriptor Byte}
    {actions : List (Option DataPlaneForwarding.Action)}
    (origin : RedPayloadOrigin c sources start.logical) (whole : start.fragments = none)
    (run : (Fragmentation.segmented (DataPlaneForwarding.lts c)
      (DataPlaneForwarding.encodeForFragmentation encodedBytes)).MTr start actions finish)
    (ready : finish.logical.datapathStage = .egressReady) (black : finish.logical.iface ∈ blackIfaces) :
    ∀ pieces, finish.fragments = some pieces → ∀ piece ∈ pieces,
      piece.header.layers = [2, 1] ∧
      piece.header.payload = finish.logical.frame.payload ∧
      piece.header.originDomain = finish.logical.frame.originDomain ∧
      piece.header.source = finish.logical.frame.packet.source ∧
      piece.header.destination = finish.logical.frame.packet.destination := by
  have stack := fragmented_black_transmission_keeps_layers c expectedEncapStack sources blackIfaces
    (DataPlaneForwarding.encodeForFragmentation encodedBytes) conditions sourceCheck blackCheck origin run ready black
  intro pieces existsPieces piece member
  rw [DataPlaneForwarding.forwarding_fragment_descriptors_match c encodedBytes run whole pieces existsPieces piece member]
  exact ⟨stack, rfl, rfl, rfl, rfl⟩

end TDN.Requirements
