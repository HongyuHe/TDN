import TDN.Semantics.SourceHeaderEncoding

namespace TDN.PacketSource

lemma matched_network_header_properties (packet : PacketPolicy.Packet) (bytes : List UInt8)
    (dataBytes : Nat) (matched : NetworkHeaderMatches packet bytes dataBytes) :
    NetworkTemplate packet ∧ bytes.length = networkHeaderSize packet ∧
    packet.hopLimit ≤ 255 ∧
    (∃ number, protocolNumber packet.protocol = some number ∧ number < 256) ∧
    bytes.length + dataBytes ≤ networkProtocolLimit packet ∧
    (2^32 ≤ packet.source → protocolNumber packet.protocol = some packet.ipv6NextHeader) := by
  rcases matched with ipv4 | ipv6
  · obtain ⟨source, destination, minimum, maximum, version, words, width, total,
      sourceField, destinationField, hop, protocol⟩ := ipv4
    have hopBound := field_bound bytes 8 1
    have protocolBound := field_bound bytes 9 1
    have sizeBound := field_bound bytes 2 2
    rw [hop] at hopBound
    rw [total] at sizeBound
    refine ⟨Or.inl ⟨source, destination, by omega, by omega⟩, ?_, by omega,
      ⟨field bytes 9 1, protocol, protocolBound⟩, ?_, ?_⟩
    · simp only [networkHeaderSize, source, ↓reduceIte]
      exact width
    · simp only [networkProtocolLimit, source, ↓reduceIte]
      omega
    · intro conflict
      omega
  · obtain ⟨source, sourceLimit, destination, destinationLimit, version, width, words,
      total, sourceField, destinationField, protocol, nextHeader, hop⟩ := ipv6
    have notIPv4 : ¬ packet.source < 2^32 := by omega
    have hopBound := field_bound bytes 7 1
    have protocolBound := field_bound bytes 6 1
    have sizeBound := field_bound bytes 4 2
    rw [← hop] at hopBound
    rw [total] at sizeBound
    refine ⟨Or.inr ⟨source, sourceLimit, destination, destinationLimit, words⟩, ?_, by omega,
      ⟨field bytes 6 1, protocol, protocolBound⟩, ?_, ?_⟩
    · simpa only [networkHeaderSize, notIPv4, ↓reduceIte] using width
    · simp only [networkProtocolLimit, notIPv4, ↓reduceIte]
      omega
    · intro _
      rw [nextHeader]
      exact protocol

lemma matched_transport_ICMP_representable (packet : PacketPolicy.Packet)
    (transport payload : List UInt8) (matched : TransportHeaderMatches packet transport payload)
    (icmp : packet.protocol ∈ ["icmp", "icmpv6"]) :
    packet.sourcePort = 0 ∧ packet.destinationPort = 0 ∧
      packet.icmpType ≤ 255 ∧ packet.icmpCode ≤ 255 := by
  rcases matched with udp | tcp | fields
  · simp only [udp.1] at icmp
    contradiction
  · simp only [tcp.1] at icmp
    contradiction
  · obtain ⟨_, _, source, destination, type, code⟩ := fields
    have typeBound := field_bound transport 0 1
    have codeBound := field_bound transport 1 1
    rw [type] at typeBound
    rw [code] at codeBound
    exact ⟨source, destination, by omega, by omega⟩

theorem decoded_IP_header_properties (datagram : Datagram) (packet : PacketPolicy.Packet)
    (body : datagram.body = .datagram packet) (decoded : datagram.Decoded) :
    NetworkTemplate packet ∧ datagram.networkHeader.length = networkHeaderSize packet ∧
      HeaderRepresentable packet ∧
      (∃ number, protocolNumber packet.protocol = some number ∧ number < 256) ∧
      datagram.Raw.length ≤ networkProtocolLimit packet := by
  rw [Datagram.Decoded, body] at decoded
  have network := matched_network_header_properties packet datagram.networkHeader datagram.Data.length decoded.2.2.1
  refine ⟨network.1, network.2.1,
    ⟨network.2.2.1, network.2.2.2.2.2,
      matched_transport_ICMP_representable packet datagram.transportHeader datagram.application decoded.2.2.2.1⟩,
    network.2.2.2.1, ?_⟩
  simpa only [Datagram.Raw, List.length_append] using network.2.2.2.2.1

end TDN.PacketSource
