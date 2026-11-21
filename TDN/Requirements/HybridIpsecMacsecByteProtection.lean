import TDN.Models.MultiProtocolByteFlows
import TDN.Requirements.MultiProtocolPacketDefinitions

namespace TDN.Requirements
open MultiProtocolForwarding

def MultiProtocolByteOrigin {Byte : Type} (sources : List Nat)
    (state : MultiProtocolForwarding.TunnelForwardingState) (_ : Byte) : Prop := MultiProtocolRedOrigin sources state

theorem multi_protocol_bytes_keep_protection {Byte : Type}
    (c : TunnelForwardingModel) (expectedEncapStack : Nat → List Nat) (sources : List Nat)
    (conditions : LocalConditions c expectedEncapStack)
    (sourceChecks : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.ip.canOriginateTraffic iface)
    {after : List (ByteFlows.PacketBytes MultiProtocolForwarding.TunnelForwardingState Byte)}
    {actions : List (ByteFlows.ByteFlowAction MultiProtocolForwarding.TunnelForwardingAction)}
    (run : (byteSystem c (MultiProtocolByteOrigin sources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => EncapStackConsistent c expectedEncapStack) after :=
  mixed_byte_forwarding_preserves_stack c expectedEncapStack (MultiProtocolByteOrigin sources) conditions
    (fun _ _ source => multi_protocol_red_initial_invariant c expectedEncapStack sources sourceChecks source) run

theorem every_mixed_black_byte_has_ordered_encryptions {Byte : Type}
    (c : TunnelForwardingModel) (expectedEncapStack : Nat → List Nat) (sources blackIfaces : List Nat)
    (conditions : LocalConditions c expectedEncapStack)
    (sourceChecks : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.ip.canOriginateTraffic iface)
    (blackChecks : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    (placement : ∀ iface, (expectedEncapStack iface).head? = some 2 → expectedEncapStack iface = [2, 1])
    {after : List (ByteFlows.PacketBytes MultiProtocolForwarding.TunnelForwardingState Byte)}
    {actions : List (ByteFlows.ByteFlowAction MultiProtocolForwarding.TunnelForwardingAction)}
    (run : (byteSystem c (MultiProtocolByteOrigin sources)).MTr [] actions after)
    (packet : ByteFlows.PacketBytes MultiProtocolForwarding.TunnelForwardingState Byte) (member : packet ∈ after)
    (ready : packet.state.datapathStage = .egressReady) (black : packet.state.iface ∈ blackIfaces)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, MultiProtocolByteOrigin sources start byte ∧
      (payloadByteOriginPath c).MTr start labels packet.state ∧
      ByteOrderedEncryptions c 1 2 start labels packet.state := by
  have safe := multi_protocol_bytes_keep_protection c expectedEncapStack sources conditions sourceChecks run
    packet member byte contains
  have layers : packet.state.frame.body.protectionLayers = [2, 1] := by
    have stack : packet.state.frame.body.protectionLayers = expectedEncapStack packet.state.iface := by
      simpa only [ready] using safe.2
    exact stack.trans (blackChecks packet.state.iface black)
  obtain ⟨start, labels, source, path⟩ :=
    PayloadByteOriginPath.every_byte_has_source_path (lts c) (MultiProtocolByteOrigin sources)
      PlainByteAssembly run packet member byte contains
  refine ⟨layers, start, labels, source, path, ?_⟩
  exact mixed_byte_path_requires_ordered_encryptions c expectedEncapStack conditions 1 2 placement path
    (multi_protocol_red_initial_invariant c expectedEncapStack sources sourceChecks source)
    (multi_protocol_red_origin_has_no_layers sources source) (by simp [layers])

end TDN.Requirements
