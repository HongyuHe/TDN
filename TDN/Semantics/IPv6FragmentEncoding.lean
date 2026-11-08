import TDN.Semantics.PacketHeaderEncoding

namespace TDN.PacketSource

def fragmentMoreBit (more : Bool) : Nat := if more then 1 else 0

def encodeIPv6FragmentHeader (packet : PacketPolicy.Packet) (dataBytes offset : Nat)
    (more : Bool) (identity : Nat) : List UInt8 :=
  encodeUnsigned 1 96 ++ encodeUnsigned 3 0 ++ encodeUnsigned 2 (8 + dataBytes) ++
  encodeUnsigned 1 44 ++ encodeUnsigned 1 packet.hopLimit ++
  encodeUnsigned 16 (packet.source - 2^128) ++ encodeUnsigned 16 (packet.destination - 2^128) ++
  encodeUnsigned 1 packet.ipv6NextHeader ++ encodeUnsigned 1 0 ++
  encodeUnsigned 2 (offset + fragmentMoreBit more) ++ encodeUnsigned 4 identity

@[simp] lemma encoded_IPv6_fragment_header_length (packet : PacketPolicy.Packet)
    (dataBytes offset identity : Nat) (more : Bool) :
    (encodeIPv6FragmentHeader packet dataBytes offset more identity).length = 48 := by
  simp [encodeIPv6FragmentHeader]

theorem encoded_IPv6_fragment_fields (packet : PacketPolicy.Packet) (data : List UInt8)
    (offset identity : Nat) (more : Bool)
    (source : 2^128 ≤ packet.source) (sourceLimit : packet.source < 2^129)
    (destination : 2^128 ≤ packet.destination) (destinationLimit : packet.destination < 2^129)
    (size : 8 + data.length < 65536) (position : offset + fragmentMoreBit more < 65536)
    (offsetAligned : offset % 8 = 0) (dataAligned : more = true → data.length % 8 = 0)
    (identifier : identity < 2^32)
    (protocolValue : protocolNumber packet.protocol = some packet.ipv6NextHeader)
    (protocolBound : packet.ipv6NextHeader < 256) :
    Fragment.IPv6Fields packet identity
      { networkHeader := encodeIPv6FragmentHeader packet data.length offset more identity,
        data := data, offset := offset, more := more } := by
  refine ⟨encoded_IPv6_fragment_header_length packet data.length offset identity more,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, dataAligned, offsetAligned⟩
  all_goals simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only
    [encodeIPv6FragmentHeader, List.append_assoc, field_append_before, field_append_after,
      encodeUnsigned_length, field_encodeUnsigned, Nat.reduceSub, Nat.reduceDiv]
  all_goals try omega
  all_goals try exact protocolValue
  all_goals cases more <;> simp [fragmentMoreBit] at * <;> omega

end TDN.PacketSource
