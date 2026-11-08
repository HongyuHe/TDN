import TDN.Semantics.SourceProcessing
import TDN.Semantics.SourceCodec

namespace TDN.PacketSource

theorem source_processing_emission_conditions (mtu : Nat → Nat)
    (minimum : ∀ iface, 1280 ≤ mtu iface) : EmissionConditions (sourceProcessing mtu) := by
  have checked : ∀ request datagrams,
      (sourceProcessing mtu).process request = .emitted datagrams →
      (Outcome.emitted datagrams).Valid request (mtu request.iface) := by
    intro request datagrams emitted
    have valid : ((sourceProcessing mtu).process request).Valid request (mtu request.iface) :=
      source_processing_valid request _ (minimum request.iface)
    rw [emitted] at valid
    exact valid
  refine {
    template := fun request datagrams emitted => (checked request datagrams emitted).1
    mtu := fun request datagrams emitted => (checked request datagrams emitted).2.1
    nonempty := fun request datagrams emitted => (checked request datagrams emitted).2.2.1
    application := fun request datagrams emitted => (checked request datagrams emitted).2.2.2.1
    decoded := ?_
    headers := ?_
    fragments := ?_
    protocolSize := ?_
    streamSize := ?_
    datagramMode := fun request datagrams emitted => (checked request datagrams emitted).2.2.2.2.2
    dfSize := ?_
    dfHeader := ?_ }
  · intro request datagrams emitted datagram member
    exact ((checked request datagrams emitted).2.2.2.2.1 datagram member).1
  · intro request datagrams emitted datagram member
    exact ((checked request datagrams emitted).2.2.2.2.1 datagram member).2.1
  · intro request datagrams emitted datagram member
    exact ((checked request datagrams emitted).2.2.2.2.1 datagram member).2.2.1
  · intro request datagrams emitted datagram member
    exact ((checked request datagrams emitted).2.2.2.2.1 datagram member).2.2.2.1
  · intro request datagrams emitted datagram member
    exact ((checked request datagrams emitted).2.2.2.2.1 datagram member).2.2.2.2.1
  · intro request datagrams emitted datagram member mode
    exact (((checked request datagrams emitted).2.2.2.2.1 datagram member).2.2.2.2.2 true mode).1 rfl
  · intro request datagrams emitted datagram member df mode
    exact (((checked request datagrams emitted).2.2.2.2.1 datagram member).2.2.2.2.2 df mode).2

theorem source_processing_error_conditions (mtu : Nat → Nat)
    (minimum : ∀ iface, 1280 ≤ mtu iface) : ErrorConditions (sourceProcessing mtu) := by
  have checked : ∀ request reason,
      (sourceProcessing mtu).process request = .error reason →
      (Outcome.error reason).Valid request (mtu request.iface) := by
    intro request reason outcome
    have valid : ((sourceProcessing mtu).process request).Valid request (mtu request.iface) :=
      source_processing_valid request _ (minimum request.iface)
    rw [outcome] at valid
    exact valid
  exact {
    unsupported := fun request outcome => checked request _ outcome
    invalidMtu := fun request outcome => checked request _ outcome
    protocolLength := fun request outcome => checked request _ outcome
    mtuExceeded := fun request outcome => checked request _ outcome }

end TDN.PacketSource
