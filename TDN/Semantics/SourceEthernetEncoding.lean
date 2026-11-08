import TDN.Semantics.EthernetHeaderEncoding
import TDN.Semantics.WholePacketEmission

namespace TDN.PacketSource

def encodeSourceEthernet (header : LayeredFrame.EthernetHeader) (payload : List UInt8) : Datagram :=
  { body := .ethernet header, application := payload, networkHeader := encodeEthernetHeader header,
    transportHeader := [], fragments := [] }

@[simp] lemma source_Ethernet_mtu_bytes (header : LayeredFrame.EthernetHeader) (payload : List UInt8) :
    (encodeSourceEthernet header payload).MtuBytes = payload.length := rfl

theorem source_Ethernet_datagram_decodes (request : Request) (header : LayeredFrame.EthernetHeader)
    (payload : List UInt8) (body : request.body = .ethernet header) (valid : request.TemplateValid) :
    (encodeSourceEthernet header payload).Decoded ∧
    (encodeSourceEthernet header payload).HeaderFrom request ∧
    (encodeSourceEthernet header payload).Raw.length = request.Overhead + payload.length := by
  simp only [Request.TemplateValid, body] at valid
  obtain ⟨source, destination, etherType, tags, netLength, transportLength, _⟩ := valid
  refine ⟨⟨rfl, encoded_Ethernet_header_matches header source destination etherType tags⟩, ?_, ?_⟩
  · simp only [Datagram.HeaderFrom, encodeSourceEthernet, body]
    exact ⟨True.intro, (encoded_Ethernet_header_length header).trans netLength.symm, True.intro⟩
  · simp only [Datagram.Raw, Datagram.Data, encodeSourceEthernet, List.nil_append,
      List.length_append, encoded_Ethernet_header_length, Request.Overhead, transportLength, Nat.add_zero]
    rw [netLength]

theorem source_Ethernet_whole_datagram_valid (request : Request) (header : LayeredFrame.EthernetHeader)
    (mtu : Nat) (body : request.body = .ethernet header) (valid : request.TemplateValid)
    (fits : request.application.length ≤ mtu) :
    (encodeSourceEthernet header request.application).asWhole.ValidFor request mtu := by
  obtain ⟨decoded, headerFrom, rawLength⟩ :=
    source_Ethernet_datagram_decodes request header request.application body valid
  have packetFits : (encodeSourceEthernet header request.application).MtuBytes ≤ mtu := fits
  refine ⟨decoded, headerFrom,
    Datagram.whole_packet_reassembles _ mtu decoded packetFits, ?_, ?_, ?_⟩
  · rw [Datagram.asWhole_raw, rawLength]
    simp only [Request.ProtocolLimit, body]
    exact Nat.le_refl _
  · intro stream
    simp only [Request.TemplateValid, body] at valid
    obtain ⟨dontFragment, mode⟩ := valid.2.2.2.2.2.2
    rw [stream] at mode
    cases mode
  · intro dontFragment mode
    exact ⟨fun _ => packetFits, True.intro⟩

end TDN.PacketSource
