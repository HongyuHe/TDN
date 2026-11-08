import TDN.Semantics.BinaryWire

namespace TDN.PacketSource

def encodeIPv4Header (packet : PacketPolicy.Packet) (dataBytes identity flags : Nat) : List UInt8 :=
  encodeUnsigned 1 (64 + packet.ipv4HeaderWords) ++
  encodeUnsigned 1 0 ++
  encodeUnsigned 2 (4 * packet.ipv4HeaderWords + dataBytes) ++
  encodeUnsigned 2 identity ++ encodeUnsigned 2 flags ++
  encodeUnsigned 1 packet.hopLimit ++
  encodeUnsigned 1 ((protocolNumber packet.protocol).getD 0) ++
  encodeUnsigned 2 0 ++ encodeUnsigned 4 packet.source ++
  encodeUnsigned 4 packet.destination ++ List.replicate (4 * packet.ipv4HeaderWords - 20) 0

lemma encoded_IPv4_header_length (packet : PacketPolicy.Packet) (dataBytes identity flags : Nat)
    (minimum : 5 ≤ packet.ipv4HeaderWords) :
    (encodeIPv4Header packet dataBytes identity flags).length = 4 * packet.ipv4HeaderWords := by
  simp only [encodeIPv4Header, List.length_append, encodeUnsigned_length,
    List.length_replicate]
  omega

theorem encoded_IPv4_header_matches (packet : PacketPolicy.Packet)
    (dataBytes identity flags protocol : Nat)
    (source : packet.source < 2^32) (destination : packet.destination < 2^32)
    (minimum : 5 ≤ packet.ipv4HeaderWords) (maximum : packet.ipv4HeaderWords ≤ 15)
    (size : 4 * packet.ipv4HeaderWords + dataBytes < 65536)
    (hop : packet.hopLimit < 256)
    (protocolValue : protocolNumber packet.protocol = some protocol) (protocolBound : protocol < 256) :
    NetworkHeaderMatches packet (encodeIPv4Header packet dataBytes identity flags) dataBytes := by
  have headerLength := encoded_IPv4_header_length packet dataBytes identity flags minimum
  apply Or.inl
  refine ⟨source, destination, ?_, ?_, ?_, ?_, headerLength, ?_, ?_, ?_, ?_, ?_⟩
  all_goals try omega
  all_goals try simp only [headerLength]
  all_goals simp (disch := (simp only [encodeUnsigned_length, List.length_append, List.length_replicate, Nat.reducePow]; omega)) only [encodeIPv4Header, List.append_assoc,
    field_append_before, field_append_after, encodeUnsigned_length, List.length_append,
    List.length_replicate, field_encodeUnsigned, protocolValue, Option.getD_some,
    Nat.reduceAdd, Nat.reduceSub, Nat.reducePow]
  all_goals omega


def encodeIPv6Header (packet : PacketPolicy.Packet) (dataBytes : Nat) : List UInt8 :=
  encodeUnsigned 1 96 ++ encodeUnsigned 3 0 ++ encodeUnsigned 2 dataBytes ++
  encodeUnsigned 1 packet.ipv6NextHeader ++ encodeUnsigned 1 packet.hopLimit ++
  encodeUnsigned 16 (packet.source - 2^128) ++ encodeUnsigned 16 (packet.destination - 2^128)

@[simp] lemma encoded_IPv6_header_length (packet : PacketPolicy.Packet) (dataBytes : Nat) :
    (encodeIPv6Header packet dataBytes).length = 40 := by
  simp [encodeIPv6Header]

theorem encoded_IPv6_header_matches (packet : PacketPolicy.Packet) (dataBytes : Nat)
    (source : 2^128 ≤ packet.source) (sourceLimit : packet.source < 2^129)
    (destination : 2^128 ≤ packet.destination) (destinationLimit : packet.destination < 2^129)
    (words : packet.ipv4HeaderWords = 0) (size : dataBytes < 65536)
    (hop : packet.hopLimit < 256)
    (protocolValue : protocolNumber packet.protocol = some packet.ipv6NextHeader)
    (protocolBound : packet.ipv6NextHeader < 256) :
    NetworkHeaderMatches packet (encodeIPv6Header packet dataBytes) dataBytes := by
  apply Or.inr
  refine ⟨source, sourceLimit, destination, destinationLimit, ?_,
    encoded_IPv6_header_length packet dataBytes, words, ?_, ?_, ?_, ?_, ?_, ?_⟩
  all_goals simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only [encodeIPv6Header, List.append_assoc,
    field_append_before, field_append_after, encodeUnsigned_length,
    field_encodeUnsigned, Nat.reduceSub, Nat.reduceDiv]
  all_goals try omega
  all_goals exact protocolValue

def encodeUDPHeader (packet : PacketPolicy.Packet) (payloadBytes : Nat) : List UInt8 :=
  encodeUnsigned 2 packet.sourcePort ++ encodeUnsigned 2 packet.destinationPort ++
  encodeUnsigned 2 (8 + payloadBytes) ++ encodeUnsigned 2 0

@[simp] lemma encoded_UDP_header_length (packet : PacketPolicy.Packet) (payloadBytes : Nat) :
    (encodeUDPHeader packet payloadBytes).length = 8 := by
  simp [encodeUDPHeader]

theorem encoded_UDP_header_matches (packet : PacketPolicy.Packet) (payload : List UInt8)
    (protocol : packet.protocol = "udp") (source : packet.sourcePort < 65536)
    (destination : packet.destinationPort < 65536) (size : 8 + payload.length < 65536) :
    TransportHeaderMatches packet (encodeUDPHeader packet payload.length) payload := by
  apply Or.inl
  refine ⟨protocol, encoded_UDP_header_length packet payload.length, ?_, ?_, ?_⟩
  all_goals simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only [encodeUDPHeader, List.append_assoc,
    field_append_before, field_append_after, encodeUnsigned_length,
    field_encodeUnsigned, Nat.reduceSub]
  simp [encodeUDPHeader]

def encodeICMPHeader (packet : PacketPolicy.Packet) : List UInt8 :=
  encodeUnsigned 1 packet.icmpType ++ encodeUnsigned 1 packet.icmpCode ++ encodeUnsigned 6 0

@[simp] lemma encoded_ICMP_header_length (packet : PacketPolicy.Packet) :
    (encodeICMPHeader packet).length = 8 := by
  simp [encodeICMPHeader]

theorem encoded_ICMP_header_matches (packet : PacketPolicy.Packet) (payload : List UInt8)
    (protocol : packet.protocol ∈ ["icmp", "icmpv6"])
    (source : packet.sourcePort = 0) (destination : packet.destinationPort = 0)
    (type : packet.icmpType < 256) (code : packet.icmpCode < 256) :
    TransportHeaderMatches packet (encodeICMPHeader packet) payload := by
  apply Or.inr
  apply Or.inr
  refine ⟨protocol, encoded_ICMP_header_length packet, source, destination, ?_, ?_⟩
  all_goals simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only [encodeICMPHeader, List.append_assoc,
    field_append_before, field_append_after, encodeUnsigned_length,
    field_encodeUnsigned, Nat.reduceSub]


def encodeTCPHeader (packet : PacketPolicy.Packet) (bytes : Nat) : List UInt8 :=
  encodeUnsigned 2 packet.sourcePort ++ encodeUnsigned 2 packet.destinationPort ++
  encodeUnsigned 4 0 ++ encodeUnsigned 4 0 ++ encodeUnsigned 1 (bytes / 4 * 16) ++
  encodeUnsigned 1 0 ++ encodeUnsigned 2 0 ++ encodeUnsigned 2 0 ++ encodeUnsigned 2 0 ++
  List.replicate (bytes - 20) 0

lemma encoded_TCP_header_length (packet : PacketPolicy.Packet) (bytes : Nat)
    (minimum : 20 ≤ bytes) : (encodeTCPHeader packet bytes).length = bytes := by
  simp only [encodeTCPHeader, List.length_append, encodeUnsigned_length, List.length_replicate]
  omega

theorem encoded_TCP_header_matches (packet : PacketPolicy.Packet) (payload : List UInt8)
    (bytes : Nat) (protocol : packet.protocol = "tcp") (source : packet.sourcePort < 65536)
    (destination : packet.destinationPort < 65536)
    (minimum : 20 ≤ bytes) (maximum : bytes ≤ 60) (aligned : bytes % 4 = 0) :
    TransportHeaderMatches packet (encodeTCPHeader packet bytes) payload := by
  have length := encoded_TCP_header_length packet bytes minimum
  apply Or.inr
  apply Or.inl
  refine ⟨protocol, ?_, ?_, ?_, ?_, ?_⟩
  · omega
  · omega
  · simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only
      [encodeTCPHeader, List.append_assoc, field_append_before, field_append_after,
        encodeUnsigned_length, field_encodeUnsigned, Nat.reduceSub]
  · simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only
      [encodeTCPHeader, List.append_assoc, field_append_before, field_append_after,
        encodeUnsigned_length, field_encodeUnsigned, Nat.reduceSub]
  · rw [length]
    simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only
      [encodeTCPHeader, List.append_assoc, field_append_before, field_append_after,
        encodeUnsigned_length, field_encodeUnsigned, Nat.reduceSub]
    omega


lemma encoded_IPv4_flags (packet : PacketPolicy.Packet) (dataBytes identity flags : Nat)
    (fits : flags < 65536) : field (encodeIPv4Header packet dataBytes identity flags) 6 2 = flags := by
  simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only
    [encodeIPv4Header, List.append_assoc, field_append_before, field_append_after,
      encodeUnsigned_length, field_encodeUnsigned, Nat.reduceSub]

lemma encoded_IPv4_identity (packet : PacketPolicy.Packet) (dataBytes identity flags : Nat)
    (fits : identity < 65536) : field (encodeIPv4Header packet dataBytes identity flags) 4 2 = identity := by
  simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only
    [encodeIPv4Header, List.append_assoc, field_append_before, field_append_after,
      encodeUnsigned_length, field_encodeUnsigned, Nat.reduceSub]

end TDN.PacketSource
