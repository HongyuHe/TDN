import TDN.Models.OriginStreamSegmentation
import TDN.Models.OriginEthernetFrameCodec

namespace TDN.PacketSource

instance requestTemplateDecidable (request : Request) : Decidable request.TemplateValid := by
  unfold Request.TemplateValid HeaderRepresentable
  cases request.body <;> dsimp <;> infer_instance

def processSource (mtu : Nat) (request : Request) : Outcome :=
  if request.TemplateValid then
    if request.MtuOverhead < mtu then
      match request.body with
      | .datagram packet =>
          if request.mode = .stream ∨ request.PacketSize ≤ request.ProtocolLimit then
            if request.mode = .datagram true ∧ mtu < request.MtuBytes then .error .mtuExceeded
            else .emitted (sourceIPDatagrams request packet mtu)
          else .error .protocolLength
      | .ethernet header =>
          if mtu < request.MtuBytes then .error .mtuExceeded
          else .emitted [(encodeSourceEthernet header request.application).asWhole]
      | _ => .error .unsupportedTemplate
    else .error .invalidMtu
  else .error .unsupportedTemplate

theorem source_processing_valid_for_representable_headers (request : Request) (mtu : Nat)
    (minimum : 1280 ≤ mtu) (representable : request.HeadersRepresentable) :
    (processSource mtu request).Valid request mtu := by
  unfold processSource
  split
  next valid =>
    split
    next room =>
      cases body : request.body with
      | datagram packet =>
        simp only
        split
        next size =>
          split
          next tooLarge =>
            refine ⟨valid, Or.inl tooLarge.1, tooLarge.2, ?_⟩
            rcases size with stream | bounded
            · rw [tooLarge.1] at stream
              cases stream
            · exact bounded
          next fits =>
            have packetRepresentable : HeaderRepresentable packet := by
              simpa only [Request.HeadersRepresentable, body] using representable
            apply source_IP_datagrams_valid request packet mtu body valid packetRepresentable minimum
            · simpa only [Request.MtuOverhead, body] using room
            · intro datagramMode
              rcases size with stream | bounded
              · obtain ⟨df, mode⟩ := datagramMode
                rw [stream] at mode
                cases mode
              · exact bounded
            · intro df
              by_contra oversized
              exact fits ⟨df, by omega⟩
        next oversized =>
          simp only [not_or, not_le] at oversized
          refine ⟨valid, ?_, oversized.2⟩
          cases mode : request.mode with
          | datagram df => exact ⟨df, rfl⟩
          | stream => exact False.elim (oversized.1 mode)
      | ethernet header =>
        simp only
        split
        next tooLarge =>
          refine ⟨valid, Or.inr ⟨header, body⟩, tooLarge, ?_⟩
          simp only [Request.ProtocolLimit, Request.PacketSize, body]
          exact Nat.le_refl _
        next fits =>
          have template := valid
          simp only [Request.TemplateValid, body] at template
          have transport := template.2.2.2.2.2.1
          have packetFits : request.application.length ≤ mtu := by
            simp only [Request.MtuBytes, Request.MtuOverhead, body, transport] at fits
            omega
          refine ⟨valid, room, by simp, ?_, ?_, ?_⟩
          · simp only [List.map_cons, List.map_nil, List.flatten_cons, List.flatten_nil,
              List.append_nil, Datagram.asWhole_application, encodeSourceEthernet]
          · intro datagram member
            have same := List.mem_singleton.mp member
            subst datagram
            exact source_Ethernet_whole_datagram_valid request header mtu body valid packetFits
          · intro df mode
            rfl
      | ipsec association contents => simp only [Request.TemplateValid, body] at valid
      | macsec association contents => simp only [Request.TemplateValid, body] at valid
      | carrier endpoint contents => simp only [Request.TemplateValid, body] at valid
    next noRoom => exact ⟨valid, by omega⟩
  next unsupported => exact unsupported

def sourceProcessing (mtu : Nat → Nat) : Processing :=
  { sourceMtu := mtu, process := fun request => processSource (mtu request.iface) request }

lemma Request.template_headers_representable (request : Request) (valid : request.TemplateValid) :
    request.HeadersRepresentable := by
  cases body : request.body <;> simp only [Request.HeadersRepresentable, body]
  case datagram packet =>
    simp only [Request.TemplateValid, body] at valid
    exact valid.2.2.2.2.2
  all_goals trivial

theorem source_processing_valid (request : Request) (mtu : Nat) (minimum : 1280 ≤ mtu) :
    (processSource mtu request).Valid request mtu := by
  by_cases valid : request.TemplateValid
  · exact source_processing_valid_for_representable_headers request mtu minimum
      (request.template_headers_representable valid)
  · simp [processSource, valid, Outcome.Valid]

lemma source_IP_emission_shape (request : Request) (packet : PacketPolicy.Packet)
    (mtu : Nat) (datagrams : List Datagram) (body : request.body = .datagram packet)
    (emitted : processSource mtu request = .emitted datagrams) :
    datagrams = sourceIPDatagrams request packet mtu := by
  unfold processSource at emitted
  split at emitted
  next valid =>
    split at emitted
    next room =>
      simp only [body] at emitted
      split at emitted
      next length =>
        split at emitted
        next oversized => cases emitted
        next fits => exact (Outcome.emitted.inj emitted).symm
      next oversized => cases emitted
    next noRoom => cases emitted
  next unsupported => cases emitted

lemma source_Ethernet_emission_shape (request : Request) (header : LayeredFrame.EthernetHeader)
    (mtu : Nat) (datagrams : List Datagram) (body : request.body = .ethernet header)
    (emitted : processSource mtu request = .emitted datagrams) :
    datagrams = [(encodeSourceEthernet header request.application).asWhole] := by
  unfold processSource at emitted
  split at emitted
  next valid =>
    split at emitted
    next room =>
      simp only [body] at emitted
      split at emitted
      next oversized => cases emitted
      next fits => exact (Outcome.emitted.inj emitted).symm
    next noRoom => cases emitted
  next unsupported => cases emitted

lemma source_IP_datagrams_have_source_headers (request : Request) (packet : PacketPolicy.Packet)
    (mtu : Nat) (datagram : Datagram) (body : request.body = .datagram packet)
    (valid : request.TemplateValid) (member : datagram ∈ sourceIPDatagrams request packet mtu) :
    ∃ payload, datagram.body = .datagram (sourceHeader request packet payload) ∧
      (packet.payloadBytes = some payload ∨ payload = request.application ∨ packet.protocol = "tcp") := by
  cases mode : request.mode with
  | stream =>
    simp only [sourceIPDatagrams, mode] at member
    obtain ⟨payload, _, rfl⟩ := List.mem_map.mp member
    refine ⟨payload, rfl, Or.inr (Or.inr ?_)⟩
    simp only [Request.TemplateValid, body] at valid
    exact valid.2.2.2.2.1 mode
  | datagram df =>
    simp only [sourceIPDatagrams, mode, List.mem_singleton] at member
    subst datagram
    exact ⟨request.application,
      (source_IP_fragmentation_preserves request packet request.application mtu).1,
      Or.inr (Or.inl rfl)⟩

end TDN.PacketSource
