import TDN.Models.MultiProtocolHeaderCoherence

namespace TDN.PacketSource

lemma Datagram.valid_source_hop_bound {datagram : Datagram} {request : Request}
    {packet : PacketPolicy.Packet} {mtu : Nat}
    (body : request.body = .datagram packet) (valid : datagram.ValidFor request mtu) :
    packet.hopLimit ≤ 255 := by
  have headerFrom := valid.2.1
  have decoded := valid.1
  cases shape : datagram.body with
  | datagram actual =>
    simp only [Datagram.HeaderFrom, shape, body] at headerFrom
    simp only [Datagram.Decoded, shape] at decoded
    have bound := matched_network_hop_bound decoded.2.2.1
    rw [headerFrom.1] at bound
    exact bound
  | ethernet actual => simp [Datagram.HeaderFrom, shape, body] at headerFrom
  | ipsec association contents => simp [Datagram.HeaderFrom, shape, body] at headerFrom
  | macsec association contents => simp [Datagram.HeaderFrom, shape, body] at headerFrom
  | macsecPdu association encryptFrames confidentialityOffset contents => simp [Datagram.HeaderFrom, shape, body] at headerFrom
  | carrier endpoint contents => simp [Datagram.HeaderFrom, shape, body] at headerFrom

lemma Datagram.valid_source_header_representable {datagram : Datagram} {request : Request}
    {packet : PacketPolicy.Packet} {mtu : Nat}
    (body : request.body = .datagram packet) (valid : datagram.ValidFor request mtu) :
    packet.hopLimit ≤ 255 ∧
    (2^32 ≤ packet.source → protocolNumber packet.protocol = some packet.ipv6NextHeader) ∧
    (packet.protocol ∈ ["icmp", "icmpv6"] →
      packet.sourcePort = 0 ∧ packet.destinationPort = 0 ∧
      packet.icmpType ≤ 255 ∧ packet.icmpCode ≤ 255) := by
  have headerFrom := valid.2.1
  have decoded := valid.1
  cases shape : datagram.body with
  | datagram actual =>
    simp only [Datagram.HeaderFrom, shape, body] at headerFrom
    simp only [Datagram.Decoded, shape] at decoded
    rw [headerFrom.1] at decoded
    refine ⟨Datagram.valid_source_hop_bound body valid, ?_, ?_⟩
    · intro ipv6
      rcases decoded.2.2.1 with first | second
      · have bound := first.1
        simp only at bound
        omega
      · have protocol := second.2.2.2.2.2.2.2.2.2.2.1
        have next := second.2.2.2.2.2.2.2.2.2.2.2.1
        exact protocol.trans (congrArg some next.symm)
    · intro icmp
      rcases decoded.2.2.2.1 with udp | tcp | control
      · simp only [List.mem_cons] at icmp
        rcases icmp with same | same <;> simp_all
      · simp only [List.mem_cons] at icmp
        rcases icmp with same | same <;> simp_all
      · refine ⟨control.2.2.1, control.2.2.2.1, ?_, ?_⟩
        · rw [← control.2.2.2.2.1]
          exact field_byte_bound datagram.transportHeader 0
        · rw [← control.2.2.2.2.2]
          exact field_byte_bound datagram.transportHeader 1
  | ethernet actual => simp [Datagram.HeaderFrom, shape, body] at headerFrom
  | ipsec association contents => simp [Datagram.HeaderFrom, shape, body] at headerFrom
  | macsec association contents => simp [Datagram.HeaderFrom, shape, body] at headerFrom
  | macsecPdu association encryptFrames confidentialityOffset contents => simp [Datagram.HeaderFrom, shape, body] at headerFrom
  | carrier endpoint contents => simp [Datagram.HeaderFrom, shape, body] at headerFrom

end TDN.PacketSource
