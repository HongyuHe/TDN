import TDN.Semantics.SourceHeaderEncoding
import TDN.Semantics.WholePacketEmission

namespace TDN.PacketSource

def sourceFlags (request : Request) : Nat :=
  if request.mode = .datagram true then 16384 else 0

lemma source_flags_fit (request : Request) : sourceFlags request < 65536 := by
  unfold sourceFlags
  split <;> decide

lemma source_flags_are_not_fragments (request : Request) :
    sourceFlags request % 8192 = 0 ∧ sourceFlags request / 8192 % 2 = 0 := by
  unfold sourceFlags
  split <;> decide

lemma source_flags_match_df (request : Request) :
    sourceFlags request / 16384 % 2 = 1 ↔ request.mode = .datagram true := by
  unfold sourceFlags
  split <;> simp_all

def sourceHeader (request : Request) (packet : PacketPolicy.Packet) (payload : List UInt8) :
    PacketPolicy.Packet :=
  { packet with
    payloadBytes := some payload
    networkBytes := some (request.Overhead + payload.length)
    ipv4FragmentOffset := if packet.source < 2^32 then some 0 else none }

def encodeSourceDatagram (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) : Datagram :=
  let header := sourceHeader request packet payload
  { body := .datagram header, application := payload,
    transportHeader := encodeTransportHeader header request.transportHeaderBytes payload.length,
    networkHeader := encodeNetworkHeader header (request.transportHeaderBytes + payload.length)
      (request.requestId % 65536) (sourceFlags request),
    fragments := [] }

lemma Request.ip_template_parts (request : Request) (packet : PacketPolicy.Packet)
    (body : request.body = .datagram packet) (valid : request.TemplateValid) :
    NetworkTemplate packet ∧ TransportTemplate packet request.transportHeaderBytes ∧
    packet.sourcePort < 65536 ∧ packet.destinationPort < 65536 ∧
    request.networkHeaderBytes = networkHeaderSize packet := by
  simp only [Request.TemplateValid, body] at valid
  obtain ⟨network, transport, sourcePort, destinationPort, _⟩ := valid
  refine ⟨?_, transport, sourcePort, destinationPort, ?_⟩
  · rcases network with ipv4 | ipv6
    · exact Or.inl ⟨ipv4.1, ipv4.2.1, ipv4.2.2.1, ipv4.2.2.2.1⟩
    · exact Or.inr ⟨ipv6.1, ipv6.2.1, ipv6.2.2.1, ipv6.2.2.2.1, ipv6.2.2.2.2.1⟩
  · rcases network with ipv4 | ipv6
    · simpa only [networkHeaderSize, ipv4.1, ↓reduceIte] using ipv4.2.2.2.2
    · have notIPv4 : ¬ packet.source < 2^32 := by have bound := ipv6.1; omega
      simpa only [networkHeaderSize, notIPv4, ↓reduceIte] using ipv6.2.2.2.2.2

theorem source_IP_datagram_decodes (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (body : request.body = .datagram packet)
    (valid : request.TemplateValid) (representable : HeaderRepresentable packet)
    (length : request.Overhead + payload.length ≤ request.ProtocolLimit) :
    (encodeSourceDatagram request packet payload).Decoded ∧
    (encodeSourceDatagram request packet payload).HeaderFrom request ∧
    (encodeSourceDatagram request packet payload).Raw.length = request.Overhead + payload.length := by
  obtain ⟨network, transport, sourcePort, destinationPort, headerLength⟩ :=
    request.ip_template_parts packet body valid
  let actual := sourceHeader request packet payload
  have actualNetwork : NetworkTemplate actual := network
  have actualTransport : TransportTemplate actual request.transportHeaderBytes := transport
  have actualRepresentable : HeaderRepresentable actual := representable
  have networkLength : networkHeaderSize actual = request.networkHeaderBytes := headerLength.symm
  have protocolLimit : networkProtocolLimit actual = request.ProtocolLimit := by
    simp [networkProtocolLimit, actual, sourceHeader, Request.ProtocolLimit, body]
  have networkMinimum : 20 ≤ request.networkHeaderBytes := by
    rcases network with ipv4 | ipv6
    · have words := ipv4.2.2.1
      simp only [networkHeaderSize, ipv4.1, ↓reduceIte] at headerLength
      omega
    · have notIPv4 : ¬ packet.source < 2^32 := by have bound := ipv6.1; omega
      simp only [networkHeaderSize, notIPv4, ↓reduceIte] at headerLength
      omega
  have udpSize : actual.protocol = "udp" → 8 + payload.length < 65536 := by
    intro udp
    have width : request.transportHeaderBytes = 8 := by
      rcases transport with first | second | third
      · exact first.2
      · have notUDP : packet.protocol ≠ "udp" := by rw [second.1]; decide
        exact False.elim (notUDP udp)
      · have notUDP : packet.protocol ≠ "udp" := by intro same; simp [same] at third
        exact False.elim (notUDP udp)
    by_cases isIPv4 : packet.source < 2^32
    · have size : request.networkHeaderBytes + request.transportHeaderBytes + payload.length ≤ 65535 := by
        simpa only [Request.Overhead, Request.ProtocolLimit, body, isIPv4, ↓reduceIte] using length
      omega
    · have size : request.networkHeaderBytes + request.transportHeaderBytes + payload.length ≤ 65575 := by
        simpa only [Request.Overhead, Request.ProtocolLimit, body, isIPv4, ↓reduceIte] using length
      have net : request.networkHeaderBytes = 40 := by simpa only [networkHeaderSize, isIPv4, ↓reduceIte] using headerLength
      omega
  have encodedTransport := source_transport_header_matches actual request.transportHeaderBytes payload
    actualTransport actualRepresentable sourcePort destinationPort udpSize
  have encodedNetwork := source_network_header_matches actual
    (request.transportHeaderBytes + payload.length) (request.requestId % 65536) (sourceFlags request)
    actualNetwork actualRepresentable (transport_template_protocol_bound actual _ actualTransport)
    (by rw [networkLength, protocolLimit]; simpa [Request.Overhead, Nat.add_assoc] using length)
  have netLength : (encodeSourceDatagram request packet payload).networkHeader.length =
      request.networkHeaderBytes := encodedNetwork.1.trans networkLength
  have transportLength : (encodeSourceDatagram request packet payload).transportHeader.length =
      request.transportHeaderBytes := encodedTransport.1
  have rawLength : (encodeSourceDatagram request packet payload).Raw.length =
      request.Overhead + payload.length := by
    simp only [Datagram.Raw, Datagram.Data, List.length_append]
    rw [netLength, transportLength]
    exact (Nat.add_assoc ..).symm
  refine ⟨?_, ?_, rawLength⟩
  · change actual.payloadBytes = some payload ∧
      actual.networkBytes = some (encodeSourceDatagram request packet payload).Raw.length ∧ _
    refine ⟨rfl, ?_, ?_, encodedTransport.2, ?_⟩
    · rw [rawLength]
      rfl
    · simp only [Datagram.Data, List.length_append]
      change NetworkHeaderMatches actual
        (encodeNetworkHeader actual (request.transportHeaderBytes + payload.length)
          (request.requestId % 65536) (sourceFlags request))
        ((encodeTransportHeader actual request.transportHeaderBytes payload.length).length + payload.length)
      rw [encodedTransport.1]
      exact encodedNetwork.2
    · intro ipv4
      have notFragments := source_flags_are_not_fragments request
      have flags : field (encodeSourceDatagram request packet payload).networkHeader 6 2 =
          sourceFlags request := by
        change field (encodeNetworkHeader actual _ _ _) 6 2 = sourceFlags request
        rw [encodeNetworkHeader, if_pos ipv4]
        exact encoded_IPv4_flags actual _ _ _ (source_flags_fit request)
      refine ⟨decoded_fragment_offset_from_field actual _ (by omega) ?_, ?_⟩
      · rw [flags, notFragments.1]
        change (if packet.source < 2^32 then some 0 else none) = some 0
        exact if_pos ipv4
      · simpa only [flags] using notFragments
  · simp only [Datagram.HeaderFrom, body]
    change actual = { packet with
      payloadBytes := some payload
      networkBytes := some (encodeSourceDatagram request packet payload).Raw.length
      ipv4FragmentOffset := if packet.source < 2^32 then some 0 else none } ∧ _
    rw [rawLength]
    exact ⟨rfl, netLength, transportLength⟩


lemma source_IP_datagram_flags (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (ipv4 : packet.source < 2^32) :
    field (encodeSourceDatagram request packet payload).networkHeader 6 2 = sourceFlags request := by
  change field (encodeNetworkHeader (sourceHeader request packet payload) _ _ _) 6 2 = _
  have source : (sourceHeader request packet payload).source < 2^32 := ipv4
  simp only [encodeNetworkHeader, source, ↓reduceIte]
  exact encoded_IPv4_flags _ _ _ _ (source_flags_fit request)

theorem source_IP_whole_datagram_valid (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (mtu : Nat) (body : request.body = .datagram packet)
    (valid : request.TemplateValid) (representable : HeaderRepresentable packet)
    (length : request.Overhead + payload.length ≤ request.ProtocolLimit)
    (fits : request.Overhead + payload.length ≤ mtu) :
    (encodeSourceDatagram request packet payload).asWhole.ValidFor request mtu := by
  obtain ⟨decoded, headerFrom, rawLength⟩ :=
    source_IP_datagram_decodes request packet payload body valid representable length
  have packetFits : (encodeSourceDatagram request packet payload).MtuBytes ≤ mtu := by
    change (encodeSourceDatagram request packet payload).Raw.length ≤ mtu
    rw [rawLength]
    exact fits
  refine ⟨decoded, headerFrom, Datagram.whole_packet_reassembles _ mtu decoded packetFits,
    ?_, ?_, ?_⟩
  · rw [Datagram.asWhole_raw, rawLength]
    exact length
  · intro _
    rw [Datagram.asWhole_raw, rawLength]
    exact fits
  · intro dontFragment mode
    refine ⟨fun _ => packetFits, ?_⟩
    change packet.source < 2^32 →
      (field (encodeSourceDatagram request packet payload).networkHeader 6 2 / 16384 % 2 = 1 ↔
        dontFragment = true)
    intro ipv4
    rw [source_IP_datagram_flags request packet payload ipv4, source_flags_match_df, mode]
    simp

end TDN.PacketSource
