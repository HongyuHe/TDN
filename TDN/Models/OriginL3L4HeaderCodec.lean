import TDN.Models.IpAndTransportHeaderCodec
import TDN.Models.ValidHeaderFieldWidths

namespace TDN.PacketSource

def TransportTemplate (packet : PacketPolicy.Packet) (bytes : Nat) : Prop :=
  (packet.protocol = "udp" ∧ bytes = 8) ∨
  (packet.protocol = "tcp" ∧ 20 ≤ bytes ∧ bytes ≤ 60 ∧ bytes % 4 = 0) ∨
  (packet.protocol ∈ ["icmp", "icmpv6"] ∧ bytes = 8)

def encodeTransportHeader (packet : PacketPolicy.Packet) (bytes payloadBytes : Nat) : List UInt8 :=
  if packet.protocol = "udp" then encodeUDPHeader packet payloadBytes
  else if packet.protocol = "tcp" then encodeTCPHeader packet bytes
  else encodeICMPHeader packet

theorem source_transport_header_matches (packet : PacketPolicy.Packet) (bytes : Nat)
    (payload : List UInt8) (template : TransportTemplate packet bytes)
    (representable : HeaderRepresentable packet)
    (source : packet.sourcePort < 65536) (destination : packet.destinationPort < 65536)
    (udpSize : packet.protocol = "udp" → 8 + payload.length < 65536) :
    (encodeTransportHeader packet bytes payload.length).length = bytes ∧
    TransportHeaderMatches packet (encodeTransportHeader packet bytes payload.length) payload := by
  rcases template with ⟨udp, width⟩ | ⟨tcp, minimum, maximum, aligned⟩ | ⟨icmp, width⟩
  · have encoding : encodeTransportHeader packet bytes payload.length =
        encodeUDPHeader packet payload.length := by simp [encodeTransportHeader, udp]
    rw [encoding, width]
    exact ⟨encoded_UDP_header_length packet payload.length,
      encoded_UDP_header_matches packet payload udp source destination (udpSize udp)⟩
  · have encoding : encodeTransportHeader packet bytes payload.length =
        encodeTCPHeader packet bytes := by simp [encodeTransportHeader, tcp]
    rw [encoding]
    exact ⟨encoded_TCP_header_length packet bytes minimum,
      encoded_TCP_header_matches packet payload bytes tcp source destination minimum maximum aligned⟩
  · have notUDP : packet.protocol ≠ "udp" := by intro same; simp [same] at icmp
    have notTCP : packet.protocol ≠ "tcp" := by intro same; simp [same] at icmp
    have encoding : encodeTransportHeader packet bytes payload.length = encodeICMPHeader packet := by
      simp [encodeTransportHeader, notUDP, notTCP]
    rw [encoding, width]
    obtain ⟨sourcePort, destinationPort, type, code⟩ := representable.2.2 icmp
    exact ⟨encoded_ICMP_header_length packet,
      encoded_ICMP_header_matches packet payload icmp sourcePort destinationPort
        (by omega) (by omega)⟩

lemma transport_template_protocol_bound (packet : PacketPolicy.Packet) (bytes : Nat)
    (template : TransportTemplate packet bytes) :
    ∃ protocol, protocolNumber packet.protocol = some protocol ∧ protocol < 256 := by
  rcases template with ⟨udp, _⟩ | ⟨tcp, _⟩ | ⟨icmp, _⟩
  · exact ⟨17, by simp [protocolNumber, udp], by decide⟩
  · exact ⟨6, by simp [protocolNumber, tcp], by decide⟩
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at icmp
    rcases icmp with first | second
    · exact ⟨1, by simp [protocolNumber, first], by decide⟩
    · exact ⟨58, by simp [protocolNumber, second], by decide⟩

def NetworkTemplate (packet : PacketPolicy.Packet) : Prop :=
  (packet.source < 2^32 ∧ packet.destination < 2^32 ∧
    5 ≤ packet.ipv4HeaderWords ∧ packet.ipv4HeaderWords ≤ 15) ∨
  (2^128 ≤ packet.source ∧ packet.source < 2^129 ∧
    2^128 ≤ packet.destination ∧ packet.destination < 2^129 ∧ packet.ipv4HeaderWords = 0)

def networkHeaderSize (packet : PacketPolicy.Packet) : Nat :=
  if packet.source < 2^32 then 4 * packet.ipv4HeaderWords else 40

def networkProtocolLimit (packet : PacketPolicy.Packet) : Nat :=
  if packet.source < 2^32 then 65535 else 65575

def encodeNetworkHeader (packet : PacketPolicy.Packet) (dataBytes identity flags : Nat) : List UInt8 :=
  if packet.source < 2^32 then encodeIPv4Header packet dataBytes identity flags
  else encodeIPv6Header packet dataBytes

theorem source_network_header_matches (packet : PacketPolicy.Packet)
    (dataBytes identity flags : Nat) (template : NetworkTemplate packet)
    (representable : HeaderRepresentable packet)
    (protocol : ∃ protocol, protocolNumber packet.protocol = some protocol ∧ protocol < 256)
    (size : networkHeaderSize packet + dataBytes ≤ networkProtocolLimit packet) :
    (encodeNetworkHeader packet dataBytes identity flags).length = networkHeaderSize packet ∧
    NetworkHeaderMatches packet (encodeNetworkHeader packet dataBytes identity flags) dataBytes := by
  obtain ⟨number, protocolValue, protocolBound⟩ := protocol
  rcases template with ipv4 | ipv6
  · obtain ⟨source, destination, minimum, maximum⟩ := ipv4
    simp only [encodeNetworkHeader, networkHeaderSize, networkProtocolLimit, source, ↓reduceIte] at size ⊢
    exact ⟨encoded_IPv4_header_length packet dataBytes identity flags minimum,
      encoded_IPv4_header_matches packet dataBytes identity flags number source destination
        minimum maximum (by omega) (by have hop := representable.1; omega)
        protocolValue protocolBound⟩
  · obtain ⟨source, sourceLimit, destination, destinationLimit, words⟩ := ipv6
    have notIPv4 : ¬ packet.source < 2^32 := by omega
    have next := representable.2.1 (by omega)
    have same : packet.ipv6NextHeader = number := Option.some.inj (next.symm.trans protocolValue)
    simp only [encodeNetworkHeader, networkHeaderSize, networkProtocolLimit, notIPv4, ↓reduceIte] at size ⊢
    exact ⟨encoded_IPv6_header_length packet dataBytes,
      encoded_IPv6_header_matches packet dataBytes source sourceLimit destination destinationLimit
        words (by omega) (by have hop := representable.1; omega) next (by omega)⟩

end TDN.PacketSource
