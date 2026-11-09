import TDN.Models.OriginIpDatagramCodec
import TDN.Models.Ipv4AndIpv6FragmentBuilder

namespace TDN.PacketSource

def encodeFragmentedSourceDatagram (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (mtu : Nat) : Datagram :=
  (encodeSourceDatagram request packet payload).fragmentIP (sourceHeader request packet payload)
    (request.requestId % 65536) mtu

lemma source_IP_fragmentation_preserves (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (mtu : Nat) :
    (encodeFragmentedSourceDatagram request packet payload mtu).body =
      (encodeSourceDatagram request packet payload).body ∧
    (encodeFragmentedSourceDatagram request packet payload mtu).application = payload ∧
    (encodeFragmentedSourceDatagram request packet payload mtu).networkHeader =
      (encodeSourceDatagram request packet payload).networkHeader ∧
    (encodeFragmentedSourceDatagram request packet payload mtu).transportHeader =
      (encodeSourceDatagram request packet payload).transportHeader := by
  unfold encodeFragmentedSourceDatagram Datagram.fragmentIP
  split <;> exact ⟨rfl, rfl, rfl, rfl⟩

theorem source_IP_fragmented_datagram_valid (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (mtu : Nat) (body : request.body = .datagram packet)
    (valid : request.TemplateValid) (representable : HeaderRepresentable packet)
    (length : request.Overhead + payload.length ≤ request.ProtocolLimit)
    (minimum : 1280 ≤ mtu)
    (streamFits : request.mode = .stream → request.Overhead + payload.length ≤ mtu)
    (dfFits : request.mode = .datagram true → request.Overhead + payload.length ≤ mtu) :
    (encodeFragmentedSourceDatagram request packet payload mtu).ValidFor request mtu := by
  let bare := encodeSourceDatagram request packet payload
  let actual := sourceHeader request packet payload
  obtain ⟨decoded, headerFrom, rawLength⟩ :=
    source_IP_datagram_decodes request packet payload body valid representable length
  obtain ⟨network, transport, sourcePort, destinationPort, headerSize⟩ :=
    request.ip_template_parts packet body valid
  have networkLength : bare.networkHeader.length = networkHeaderSize actual := by
    have headerFromParts := headerFrom
    simp only [Datagram.HeaderFrom, body] at headerFromParts
    have size := headerFromParts.2.1
    change bare.networkHeader.length = request.networkHeaderBytes at size
    exact size.trans headerSize
  have actualLimit : networkProtocolLimit actual = request.ProtocolLimit := by
    simp [networkProtocolLimit, actual, sourceHeader, Request.ProtocolLimit, body]
  have protocol : ∃ number, number < 256 ∧ protocolNumber actual.protocol = some number := by
    obtain ⟨number, equation, bound⟩ := transport_template_protocol_bound packet _ transport
    exact ⟨number, bound, equation⟩
  have reassembles := bare.fragment_IP_reassembles actual (request.requestId % 65536) mtu rfl
    decoded network representable protocol
    (Nat.mod_lt _ (by decide)) networkLength (by rw [actualLimit, rawLength]; exact length) minimum
  have preserved := source_IP_fragmentation_preserves request packet payload mtu
  have raw : (encodeFragmentedSourceDatagram request packet payload mtu).Raw = bare.Raw := by
    simp only [Datagram.Raw, Datagram.Data, preserved.2.2.1, preserved.2.2.2, preserved.2.1]
    rfl
  have decodedResult : (encodeFragmentedSourceDatagram request packet payload mtu).Decoded := by
    unfold encodeFragmentedSourceDatagram Datagram.fragmentIP
    split <;> exact decoded
  have headerResult : (encodeFragmentedSourceDatagram request packet payload mtu).HeaderFrom request := by
    unfold encodeFragmentedSourceDatagram Datagram.fragmentIP
    split <;> exact headerFrom
  refine ⟨decodedResult, headerResult, reassembles, ?_, ?_, ?_⟩
  · rw [raw, rawLength]
    exact length
  · intro mode
    rw [raw, rawLength]
    exact streamFits mode
  · intro dontFragment mode
    refine ⟨?_, ?_⟩
    · intro df
      subst dontFragment
      change (encodeFragmentedSourceDatagram request packet payload mtu).MtuBytes ≤ mtu
      simp only [Datagram.MtuBytes, preserved.1]
      rw [raw, rawLength]
      exact dfFits mode
    · simp only [preserved.1]
      change actual.source < 2^32 →
        (field (encodeFragmentedSourceDatagram request packet payload mtu).networkHeader 6 2 /
          16384 % 2 = 1 ↔ dontFragment = true)
      intro ipv4
      rw [preserved.2.2.1, source_IP_datagram_flags request packet payload ipv4,
        source_flags_match_df, mode]
      simp

end TDN.PacketSource
