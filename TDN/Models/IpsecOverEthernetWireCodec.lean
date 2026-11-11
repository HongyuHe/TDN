import TDN.Models.InnermostPacketReconstruction

namespace TDN.IPsecFrameEncoding
open LayeredFrame PacketSource


def IPLinkHeader (packet : PacketPolicy.Packet) : EthernetHeader :=
  ⟨0, 0, if packet.source < 2^32 then 2048 else 34525, []⟩


def linkEncoding {Key : Type} (codec : Codec Key) (frame : LayeredFrame.Frame) : LinkAdmission.Frame :=
  let source := canonicalRoot frame
  match frame.visibleHeader with
  | some packet =>
      let header := IPLinkHeader packet
      ⟨header, encodeEthernetHeader header, (bareEmission codec source frame).Raw⟩
  | none =>
      let header := frame.body.originalEthernet.getD ⟨0, 0, 0, []⟩
      ⟨header, source.networkHeader, source.application⟩

lemma IP_link_header_decoded (packet : PacketPolicy.Packet) :
    EthernetHeaderMatches (IPLinkHeader packet) (encodeEthernetHeader (IPLinkHeader packet)) := by
  apply encoded_Ethernet_header_matches
  · change 0 < 2^48; decide
  · change 0 < 2^48; decide
  · unfold IPLinkHeader
    split <;> decide
  · simp [IPLinkHeader]


theorem encoded_link_describes_reachable_IPsec_frame {Key : Type} (codec : Codec Key)
    (frame : LayeredFrame.Frame) (decoded : (canonicalRoot frame).Decoded)
    (shape : frame.body.IPsecOnly KnownIPv4Seal)
    (originalIP : frame.body.originalHeader = (canonicalRoot frame).body.originalHeader)
    (originalEthernet : frame.body.originalEthernet = (canonicalRoot frame).body.originalEthernet)
    (payload : frame.payload = LinkAdmission.payloadCode (canonicalRoot frame).application)
    (coherent : frame.HeadersCoherent) (limit : Nat → Nat)
    (budget : MultiProtocolForwarding.BodySizeBudget limit frame.body) :
    (linkEncoding codec frame).Describes frame := by
  cases visible : frame.visibleHeader with
  | some actual =>
    have properties := bare_emission_IP_properties codec (canonicalRoot frame) decoded frame shape originalIP
      originalEthernet coherent limit budget actual visible
    obtain ⟨nominal, nominalVisible, identity⟩ := frame.coherent_visible coherent actual visible
    simp only [LinkAdmission.Frame.Describes, visible, linkEncoding]
    refine ⟨IP_link_header_decoded actual, ?_, ?_⟩
    · unfold IPLinkHeader
      split <;> rfl
    · cases body : frame.body with
      | datagram header =>
        have same : nominal = header := by simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible.symm
        subst nominal
        have sourceBody := source_IP_body_from_original (canonicalRoot frame) decoded header
          (by simpa only [body, Body.originalHeader] using originalIP)
        have sourceDecoded := decoded
        rw [Datagram.Decoded, sourceBody] at sourceDecoded
        have actualSame : frame.activeHeader.getD header = actual := by
          simpa only [Frame.visibleHeader, body, Body.visibleHeader, Option.some.injEq] using visible
        refine ⟨leafNetwork (canonicalRoot frame) header actual, (canonicalRoot frame).transportHeader,
          (canonicalRoot frame).application, ?_, ?_, ?_, ?_⟩
        · simp only [bareEmission, body, actualSame, Datagram.Raw, Datagram.Data, List.append_assoc]
        · simpa only [bareEmission, body, actualSame, Datagram.Data, List.length_append] using properties.2.1
        · intro original plain
          have actualPayload : actual.payloadBytes = some (canonicalRoot frame).application := by
            rw [identity.actual_is_nominal_with_hop]
            exact sourceDecoded.1
          exact ⟨actualPayload, payload⟩
        · exact Or.inl (forwarded_transport_header_matches (canonicalRoot frame) header actual sourceBody decoded identity)
      | ipsec association contents =>
        have actualSame : frame.activeHeader.getD (outerHeader association.sender association.receiver "esp" 0 0) = actual := by
          simpa only [Frame.visibleHeader, body, Body.visibleHeader, Option.some.injEq] using visible
        refine ⟨(bareEmission codec (canonicalRoot frame) frame).networkHeader, [],
          protectedData codec (canonicalRoot frame) association contents frame.hiddenHeaders, ?_, ?_, ?_, ?_⟩
        · simp only [bareEmission, body, Datagram.Raw, Datagram.Data, List.nil_append, List.append_nil]
        · simpa only [bareEmission, body, Datagram.Data, List.nil_append, List.length_nil, Nat.zero_add] using properties.2.1
        · intro original plain
          cases plain
        · refine Or.inr ⟨?_, rfl, ?_⟩
          · have same : nominal = outerHeader association.sender association.receiver "esp" 0 0 := by
              simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible.symm
            rw [identity.actual_is_nominal_with_hop, same]
            rfl
          · unfold protectedData
            rw [ESPWire.encoded_ESP_length codec.primitive _ _ _ _ _ _ (codec.parameters association).ivLength]
            unfold PacketLength.alignedWireLength
            omega
      | ethernet header => simp [body, Body.visibleHeader] at nominalVisible
      | macsec association contents => simp [body, Body.IPsecOnly] at shape
      | macsecPdu association encryptFrames confidentialityOffset contents => simp [body, Body.IPsecOnly] at shape
      | carrier endpoint contents => simp [body, Body.IPsecOnly] at shape
  | none =>
    cases body : frame.body with
    | datagram header => simp [Frame.visibleHeader, body, Body.visibleHeader] at visible
    | ipsec association contents => simp [Frame.visibleHeader, body, Body.visibleHeader] at visible
    | macsec association contents => simp [body, Body.IPsecOnly] at shape
    | macsecPdu association encryptFrames confidentialityOffset contents => simp [body, Body.IPsecOnly] at shape
    | carrier endpoint contents => simp [body, Body.IPsecOnly] at shape
    | ethernet header =>
      have sourceBody : (canonicalRoot frame).body = .ethernet header := by
        cases sourceCase : (canonicalRoot frame).body with
        | ethernet nominal =>
          have same : header = nominal := by simpa only [body, sourceCase, Body.originalEthernet,
            Option.some.injEq] using originalEthernet
          simpa only [same] using sourceCase
        | datagram nominal => simp [body, sourceCase, Body.originalEthernet] at originalEthernet
        | ipsec association contents => simp [Datagram.Decoded, sourceCase] at decoded
        | macsec association contents => simp [Datagram.Decoded, sourceCase] at decoded
        | macsecPdu association encryptFrames confidentialityOffset contents => simp [Datagram.Decoded, sourceCase] at decoded
        | carrier endpoint contents => simp [Datagram.Decoded, sourceCase] at decoded
      rw [Datagram.Decoded, sourceBody] at decoded
      simp only [LinkAdmission.Frame.Describes, visible, linkEncoding, body, Body.originalEthernet,
        Option.getD_some, LinkAdmission.Frame.DescribesBody, LinkAdmission.Frame.Decoded]
      exact ⟨⟨decoded.2, True.intro⟩, fun original plain => payload⟩

end TDN.IPsecFrameEncoding
