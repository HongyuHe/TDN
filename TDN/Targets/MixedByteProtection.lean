import TDN.Semantics.MixedByteFlows
import TDN.Targets.MultiProtocolPackets

namespace TDN.Targets
open MultiProtocolExecution

def MixedByteOrigin {Byte : Type} (sources : List Nat)
    (state : MultiProtocolExecution.State) (_ : Byte) : Prop := MixedRedOrigin sources state

theorem mixed_bytes_keep_protection {Byte : Type}
    (c : Config) (layout : Nat → List Nat) (sources : List Nat)
    (conditions : LocalConditions c layout)
    (sourceChecks : ∀ port ∈ sources, layout port = [] ∧ c.ip.payloadOrigin port)
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem c (MixedByteOrigin sources)).MTr [] actions after) :
    ByteFlows.Safe (fun _ => StackInvariant c layout) after :=
  mixed_byte_execution_preserves_stack c layout (MixedByteOrigin sources) conditions
    (fun _ _ source => mixed_red_initial_invariant c layout sources sourceChecks source) run

theorem every_mixed_black_byte_has_ordered_encryptions {Byte : Type}
    (c : Config) (layout : Nat → List Nat) (sources blackPorts : List Nat)
    (conditions : LocalConditions c layout)
    (sourceChecks : ∀ port ∈ sources, layout port = [] ∧ c.ip.payloadOrigin port)
    (blackChecks : ∀ port ∈ blackPorts, layout port = [2, 1])
    (placement : ∀ port, (layout port).head? = some 2 → layout port = [2, 1])
    {after : List (ByteFlows.Carrier MultiProtocolExecution.State Byte)}
    {actions : List (ByteFlows.Action MultiProtocolExecution.Action)}
    (run : (byteSystem c (MixedByteOrigin sources)).MTr [] actions after)
    (packet : ByteFlows.Carrier MultiProtocolExecution.State Byte) (member : packet ∈ after)
    (ready : packet.state.phase = .ready) (black : packet.state.port ∈ blackPorts)
    (byte : Byte) (contains : byte ∈ packet.bytes) :
    packet.state.frame.body.protectionLayers = [2, 1] ∧
    ∃ start labels, MixedByteOrigin sources start byte ∧
      (byteLineage c).MTr start labels packet.state ∧
      ByteOrderedEncryptions c 1 2 start labels packet.state := by
  have safe := mixed_bytes_keep_protection c layout sources conditions sourceChecks run
    packet member byte contains
  have layers : packet.state.frame.body.protectionLayers = [2, 1] := by
    have stack : packet.state.frame.body.protectionLayers = layout packet.state.port := by
      simpa only [ready] using safe.2
    exact stack.trans (blackChecks packet.state.port black)
  obtain ⟨start, labels, source, path⟩ :=
    ByteLineage.every_byte_has_source_path (lts c) (MixedByteOrigin sources)
      PlainByteAssembly run packet member byte contains
  refine ⟨layers, start, labels, source, path, ?_⟩
  exact mixed_byte_path_requires_ordered_encryptions c layout conditions 1 2 placement path
    (mixed_red_initial_invariant c layout sources sourceChecks source)
    (mixed_red_origin_has_no_layers sources source) (by simp [layers])

end TDN.Targets
