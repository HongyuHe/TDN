import TDN.Models.IpsecEgressFragmentAndEmit
import TDN.Models.EthernetAndVlanWireCodec
import TDN.Models.PayloadToNatEncoding

namespace TDN.PacketSource

lemma matched_transport_template (packet : PacketPolicy.Packet) (transport payload : List UInt8)
    (matched : TransportHeaderMatches packet transport payload) :
    TransportTemplate packet transport.length ∧ packet.sourcePort < 65536 ∧
      packet.destinationPort < 65536 ∧ (packet.protocol = "udp" → 8 + payload.length < 65536) := by
  rcases matched with udp | tcp | icmp
  · have source := field_bound transport 0 2
    have destination := field_bound transport 2 2
    have size := field_bound transport 4 2
    rw [udp.2.2.1] at source
    rw [udp.2.2.2.1] at destination
    rw [udp.2.2.2.2, udp.2.1] at size
    exact ⟨Or.inl ⟨udp.1, udp.2.1⟩, source, destination, fun _ => size⟩
  · have source := field_bound transport 0 2
    have destination := field_bound transport 2 2
    rw [tcp.2.2.2.1] at source
    rw [tcp.2.2.2.2.1] at destination
    refine ⟨Or.inr (Or.inl ⟨tcp.1, tcp.2.1, tcp.2.2.1, ?_⟩), source, destination, ?_⟩
    · have width := tcp.2.2.2.2.2
      omega
    · intro udp
      rw [udp] at tcp
      simp only [String.reduceEq, false_and] at tcp
  · refine ⟨Or.inr (Or.inr ⟨icmp.1, icmp.2.1⟩), ?_, ?_, ?_⟩
    · rw [icmp.2.2.1]; decide
    · rw [icmp.2.2.2.1]; decide
    · intro udp
      simp [udp] at icmp


def canonicalIPRoot (header : PacketPolicy.Packet) : Datagram :=
  let payload := header.payloadBytes.getD []
  let total := header.networkBytes.getD 0
  let transportBytes := total - networkHeaderSize header - payload.length
  { body := .datagram header, application := payload,
    networkHeader := encodeNetworkHeader header (transportBytes + payload.length) 0 0,
    transportHeader := encodeTransportHeader header transportBytes payload.length, fragments := [] }


theorem standard_IP_root_decodes (source : Datagram) (header : PacketPolicy.Packet)
    (body : source.body = .datagram header) (decoded : source.Decoded) :
    (canonicalIPRoot header).Decoded ∧ (canonicalIPRoot header).application = source.application := by
  have properties := decoded_IP_header_properties source header body decoded
  have fields := decoded
  rw [Datagram.Decoded, body] at fields
  have transport := matched_transport_template header source.transportHeader source.application fields.2.2.2.1
  have payload : header.payloadBytes.getD [] = source.application := by rw [fields.1]; rfl
  have total : header.networkBytes.getD 0 = source.Raw.length := by rw [fields.2.1]; rfl
  have width : source.Raw.length - networkHeaderSize header - source.application.length = source.transportHeader.length := by
    rw [← properties.2.1]
    simp only [Datagram.Raw, Datagram.Data, List.length_append]
    omega
  have encodedTransport := source_transport_header_matches header source.transportHeader.length
    source.application transport.1 properties.2.2.1 transport.2.1 transport.2.2.1 transport.2.2.2
  have size : networkHeaderSize header + (source.transportHeader.length + source.application.length) ≤
      networkProtocolLimit header := by
    rw [← properties.2.1]
    simpa only [Datagram.Raw, Datagram.Data, List.length_append] using properties.2.2.2.2
  have encodedNetwork := source_network_header_matches header
    (source.transportHeader.length + source.application.length) 0 0 properties.1 properties.2.2.1
    properties.2.2.2.1 size
  have rootSame : canonicalIPRoot header =
      { body := .datagram header, application := source.application,
        networkHeader := encodeNetworkHeader header (source.transportHeader.length + source.application.length) 0 0,
        transportHeader := encodeTransportHeader header source.transportHeader.length source.application.length,
        fragments := [] } := by
    simp only [canonicalIPRoot, payload, total, width]
  have rawLength : (canonicalIPRoot header).Raw.length = source.Raw.length := by
    rw [rootSame]
    simp only [Datagram.Raw, Datagram.Data, List.length_append, encodedNetwork.1, encodedTransport.1]
    rw [← properties.2.1]
  refine ⟨?_, payload⟩
  rw [rootSame]
  change header.payloadBytes = some source.application ∧ _
  refine ⟨fields.1, ?_, ?_, encodedTransport.2, ?_⟩
  · have sameLength := rawLength
    rw [rootSame] at sameLength
    rw [sameLength]
    exact fields.2.1
  · simpa only [Datagram.Data, List.length_append, encodedTransport.1] using encodedNetwork.2
  · intro ipv4
    have initial := fields.2.2.2.2 ipv4
    have offset : header.ipv4FragmentOffset = some 0 := by
      have decodedOffset := initial.1
      unfold PacketPolicy.Packet.IPv4FragmentOffsetDecoded at decodedOffset
      rw [← field_two_bytes source.networkHeader 6 decodedOffset.1, initial.2.1] at decodedOffset
      exact decodedOffset.2
    let bytes := encodeNetworkHeader header (source.transportHeader.length + source.application.length) 0 0
    have flags : field bytes 6 2 = 0 := by
      unfold bytes encodeNetworkHeader
      rw [if_pos ipv4]
      exact encoded_IPv4_flags _ _ _ _ (by decide)
    have available : 8 ≤ bytes.length := by
      rw [encodedNetwork.1]
      rcases properties.1 with first | second
      · simp only [networkHeaderSize, ipv4, ↓reduceIte]
        have words := first.2.2.1
        omega
      · have sourceBound := second.1
        omega
    refine ⟨decoded_fragment_offset_from_field header bytes available ?_, ?_⟩
    · rw [flags]
      exact offset
    · rw [flags]
      decide


lemma matched_Ethernet_header_bounds (header : LayeredFrame.EthernetHeader) (bytes : List UInt8)
    (matched : EthernetHeaderMatches header bytes) :
    header.source < 2^48 ∧ header.destination < 2^48 ∧ header.etherType < 65536 ∧
      ∀ tag ∈ header.vlanTags, tag < 65536 := by
  have source := field_bound bytes 6 6
  have destination := field_bound bytes 0 6
  have etherType := field_bound bytes (12 + 4 * header.vlanTags.length) 2
  rw [matched.2.2.1] at source
  rw [matched.2.1] at destination
  rw [matched.2.2.2.2] at etherType
  refine ⟨source, destination, etherType, ?_⟩
  intro tag member
  obtain ⟨index, within, same⟩ := List.mem_iff_getElem.mp member
  have tagField := (matched.2.2.2.1 index within).2
  have byteBound := field_bound bytes (14 + index * 4) 2
  have tagEqual : tag = field bytes (14 + index * 4) 2 := by
    simpa only [List.getElem?_eq_getElem within, same, Option.some.injEq] using tagField
  rw [tagEqual]
  exact byteBound


def canonicalRoot (frame : LayeredFrame.Frame) : Datagram :=
  match frame.body.originalHeader with
  | some header => canonicalIPRoot header
  | none =>
      let header := frame.body.originalEthernet.getD ⟨0, 0, 0, []⟩
      { body := .ethernet header, application := LinkAdmission.decodePayload frame.payload,
        networkHeader := encodeEthernetHeader header, transportHeader := [], fragments := [] }


theorem standard_root_properties (source : Datagram) (decoded : source.Decoded)
    (frame : LayeredFrame.Frame)
    (originalIP : frame.body.originalHeader = source.body.originalHeader)
    (originalEthernet : frame.body.originalEthernet = source.body.originalEthernet)
    (payload : frame.payload = LinkAdmission.payloadCode source.application) :
    (canonicalRoot frame).Decoded ∧ (canonicalRoot frame).application = source.application ∧
    (canonicalRoot frame).body.originalHeader = source.body.originalHeader ∧
    (canonicalRoot frame).body.originalEthernet = source.body.originalEthernet := by
  cases body : source.body with
  | datagram header =>
    have root : canonicalRoot frame = canonicalIPRoot header := by
      unfold canonicalRoot
      rw [originalIP, body, LayeredFrame.Body.originalHeader]
    rw [root]
    have valid := standard_IP_root_decodes source header body decoded
    exact ⟨valid.1, valid.2, by rfl, by rfl⟩
  | ethernet header =>
    have root : canonicalRoot frame =
        { body := .ethernet header, application := source.application,
          networkHeader := encodeEthernetHeader header, transportHeader := [], fragments := [] } := by
      unfold canonicalRoot
      rw [originalIP, originalEthernet, body]
      simp only [LayeredFrame.Body.originalHeader, LayeredFrame.Body.originalEthernet,
        Option.getD_some, payload, LinkAdmission.decodePayload_payloadCode]
    rw [root]
    have fields := decoded
    rw [Datagram.Decoded, body] at fields
    have bounds := matched_Ethernet_header_bounds header source.networkHeader fields.2
    exact ⟨⟨rfl, encoded_Ethernet_header_matches header bounds.1 bounds.2.1 bounds.2.2.1 bounds.2.2.2⟩,
      rfl, by rfl, by rfl⟩
  | ipsec association contents => simp [Datagram.Decoded, body] at decoded
  | macsec association contents => simp [Datagram.Decoded, body] at decoded
  | macsecPdu association encryptFrames confidentialityOffset contents => simp [Datagram.Decoded, body] at decoded
  | carrier endpoint contents => simp [Datagram.Decoded, body] at decoded

end TDN.PacketSource
