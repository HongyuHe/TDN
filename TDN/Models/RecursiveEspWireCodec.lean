import TDN.Models.EspAeadWireCodec
import TDN.Models.HopLimitUpdatedDatagramCodec
import TDN.Models.IpsecOnlyEncapInvariant

namespace TDN.IPsecFrameEncoding
open PacketSource LayeredFrame ESPWire

structure Parameters where
  sequence : Nat
  iv : List UInt8
  sequencePositive : 0 < sequence
  sequenceFits : sequence < 2^32
  ivLength : iv.length = 8

structure Codec (Key : Type) where
  primitive : GCMPrimitive Key
  key : DataPlaneForwarding.TunnelSAStamp → Key
  parameters : DataPlaneForwarding.TunnelSAStamp → Parameters

variable {Key : Type}

def KnownIPv4Seal (association : DataPlaneForwarding.TunnelSAStamp) : Prop :=
  association.sender < 2^32 ∧ association.receiver < 2^32 ∧ association.association < 2^32


def nextHeader (body : Body) : Nat :=
  match body.visibleHeader with
  | none => 0
  | some header => if header.source < 2^32 then 4 else 41

lemma next_header_bound (body : Body) : nextHeader body < 256 := by
  unfold nextHeader
  split
  · decide
  · split <;> decide


def networkLength : Body → Option Nat
  | .datagram header => header.networkBytes
  | .ipsec _ contents => (networkLength contents).map (PacketLength.alignedWireLength 4 2 52)
  | .ethernet _ | .macsec _ _ | .carrier _ _ => none


def leafNetwork (source : Datagram) (nominal actual : PacketPolicy.Packet) : List UInt8 :=
  forwardedNetworkHeader source nominal actual


def encodeBody (codec : Codec Key) (source : Datagram) (payload : List UInt8) :
    Body → Option PacketPolicy.Packet → List (Option PacketPolicy.Packet) → List UInt8
  | .datagram nominal, active, _ =>
      leafNetwork source nominal (active.getD nominal) ++ source.transportHeader ++ payload
  | .ethernet _, _, _ => source.networkHeader ++ payload
  | .ipsec association contents, active, hidden =>
      let inner := encodeBody codec source payload contents (hidden.head?.getD none) (hidden.drop 1)
      let parameters := codec.parameters association
      let protectedBytes := encodeESP codec.primitive (codec.key association)
        association.association parameters.sequence parameters.iv inner (nextHeader contents)
      let header := active.getD (outerHeader association.sender association.receiver "esp" 0 0)
      encodeNetworkHeader header protectedBytes.length 0 0 ++ protectedBytes
  | .macsec _ _, _, _ | .carrier _ _, _, _ => []


def decodeBody (codec : Codec Key) (source : Datagram) :
    Body → Option PacketPolicy.Packet → List (Option PacketPolicy.Packet) → List UInt8 → Option (List UInt8)
  | .datagram _, _, _, bytes =>
      some (bytes.drop (source.networkHeader.length + source.transportHeader.length))
  | .ethernet _, _, _, bytes => some (bytes.drop source.networkHeader.length)
  | .ipsec association contents, active, hidden, bytes =>
      let header := active.getD (outerHeader association.sender association.receiver "esp" 0 0)
      let protectedBytes := bytes.drop (networkHeaderSize header)
      (decodeESP codec.primitive (codec.key association) protectedBytes).bind fun decoded =>
        if decoded.2 = nextHeader contents then
          decodeBody codec source contents (hidden.head?.getD none) (hidden.drop 1) decoded.1
        else none
  | .macsec _ _, _, _, _ | .carrier _ _, _, _, _ => none


def encodeFrame (codec : Codec Key) (source : Datagram) (payload : List UInt8) (frame : Frame) :
    List UInt8 := encodeBody codec source payload frame.body frame.activeHeader frame.hiddenHeaders


def decodeFrame (codec : Codec Key) (source : Datagram) (frame : Frame) (bytes : List UInt8) :
    Option (Body × List UInt8) :=
  (decodeBody codec source frame.body frame.activeHeader frame.hiddenHeaders bytes).map
    (fun payload => (frame.body, payload))

lemma known_outer_header_size (association : DataPlaneForwarding.TunnelSAStamp) (known : KnownIPv4Seal association)
    (active : Option PacketPolicy.Packet)
    (identity : HeaderIdentity
      (active.getD (outerHeader association.sender association.receiver "esp" 0 0))
      (outerHeader association.sender association.receiver "esp" 0 0)) (dataBytes : Nat) :
    networkHeaderSize (active.getD (outerHeader association.sender association.receiver "esp" 0 0)) = 20 ∧
    (encodeNetworkHeader (active.getD (outerHeader association.sender association.receiver "esp" 0 0))
      dataBytes 0 0).length = 20 := by
  rw [identity.actual_is_nominal_with_hop]
  simp only [networkHeaderSize, encodeNetworkHeader, outerHeader, InternetAddresses.headerWords,
    known.1, ↓reduceIte]
  exact ⟨True.intro, encoded_IPv4_header_length _ dataBytes 0 0 (by norm_num)⟩

theorem initial_body_serialization (codec : Codec Key) (source : Datagram) (decoded : source.Decoded) :
    encodeBody codec source source.application source.body none [] = source.Raw := by
  cases body : source.body with
  | datagram header =>
    simp only [encodeBody, Option.getD_none, leafNetwork, forwardedNetworkHeader,
      ↓reduceIte, Datagram.Raw, Datagram.Data, List.append_assoc]
  | ethernet header =>
    simp only [Datagram.Decoded, body] at decoded
    simp only [encodeBody, Datagram.Raw, Datagram.Data, decoded.1, List.nil_append]
  | ipsec association contents => simp [Datagram.Decoded, body] at decoded
  | macsec association contents => simp [Datagram.Decoded, body] at decoded
  | carrier endpoint contents => simp [Datagram.Decoded, body] at decoded


lemma source_IP_body_from_original (source : Datagram) (decoded : source.Decoded)
    (header : PacketPolicy.Packet) (same : some header = source.body.originalHeader) :
    source.body = .datagram header := by
  cases sourceCase : source.body with
  | datagram nominal =>
    have equal : header = nominal := by simpa [Body.originalHeader, sourceCase] using same
    simpa only [equal] using sourceCase
  | ethernet nominal => simp [Body.originalHeader, sourceCase] at same
  | ipsec association contents => simp [Datagram.Decoded, sourceCase] at decoded
  | macsec association contents => simp [Datagram.Decoded, sourceCase] at decoded
  | carrier endpoint contents => simp [Datagram.Decoded, sourceCase] at decoded

lemma ESP_network_length_at_least_inner (bytes : Nat) :
    bytes ≤ PacketLength.alignedWireLength 4 2 52 bytes := by
  have padded := padded_length bytes
  unfold PacketLength.alignedWireLength
  omega


theorem decode_encoded_body (codec : Codec Key) (source : Datagram) (payload : List UInt8)
    (decoded : source.Decoded) (body : Body)
    (shape : body.IPsecOnly KnownIPv4Seal)
    (originalIP : body.originalHeader = source.body.originalHeader)
    (originalEthernet : body.originalEthernet = source.body.originalEthernet)
    (active : Option PacketPolicy.Packet) (hidden : List (Option PacketPolicy.Packet))
    (coherent : body.HeadersCoherent active hidden) :
    decodeBody codec source body active hidden (encodeBody codec source payload body active hidden) =
      some payload := by
  induction body generalizing active hidden with
  | datagram nominal =>
    have sourceBody : source.body = .datagram nominal := by
      cases sourceCase : source.body with
      | datagram sourceHeader =>
        have same : nominal = sourceHeader := by simpa [Body.originalHeader, sourceCase] using originalIP
        simpa only [same] using sourceCase
      | ethernet header => simp [Body.originalHeader, sourceCase] at originalIP
      | ipsec association contents => simp [Datagram.Decoded, sourceCase] at decoded
      | macsec association contents => simp [Datagram.Decoded, sourceCase] at decoded
      | carrier endpoint contents => simp [Datagram.Decoded, sourceCase] at decoded
    have width := (forwarded_network_header_matches source nominal (active.getD nominal)
      sourceBody decoded coherent.1).1
    have prefixLength : (leafNetwork source nominal (active.getD nominal) ++ source.transportHeader).length =
        source.networkHeader.length + source.transportHeader.length := by
      simp only [List.length_append, leafNetwork, width]
    simp only [encodeBody, decodeBody]
    rw [← prefixLength, List.drop_left]
  | ethernet header =>
    simp only [encodeBody, decodeBody]
    rw [List.drop_left]
  | ipsec association contents ih =>
    obtain ⟨known, contentsShape, visible⟩ := shape
    obtain ⟨identity, inner, rest, sameHidden, contentsCoherent⟩ := coherent
    subst hidden
    have originalContentsIP : contents.originalHeader = source.body.originalHeader := originalIP
    have originalContentsEthernet : contents.originalEthernet = source.body.originalEthernet := originalEthernet
    have recurse := ih contentsShape originalContentsIP originalContentsEthernet inner rest contentsCoherent
    let encodedContents := encodeBody codec source payload contents inner rest
    let parameters := codec.parameters association
    let protectedBytes := encodeESP codec.primitive (codec.key association)
      association.association parameters.sequence parameters.iv encodedContents (nextHeader contents)
    have headerSize := known_outer_header_size association known active identity protectedBytes.length
    simp only [encodeBody, decodeBody, List.head?_cons, Option.getD_some, List.drop_succ_cons,
      List.drop_zero]
    change (decodeESP codec.primitive (codec.key association)
      ((encodeNetworkHeader (active.getD (outerHeader association.sender association.receiver "esp" 0 0))
        protectedBytes.length 0 0 ++ protectedBytes).drop
          (networkHeaderSize (active.getD (outerHeader association.sender association.receiver "esp" 0 0))))).bind _ = _
    rw [← headerSize.2.trans headerSize.1.symm, List.drop_left]
    rw [decode_encoded_ESP codec.primitive (codec.key association) association.association parameters.sequence
      parameters.iv encodedContents (nextHeader contents) parameters.ivLength (next_header_bound contents)]
    simp only [Option.bind_some, ↓reduceIte]
    exact recurse
  | macsec association contents ih => exact False.elim shape
  | carrier endpoint contents ih => exact False.elim shape


theorem encoded_body_network_length (codec : Codec Key) (source : Datagram)
    (decoded : source.Decoded) (body : Body)
    (shape : body.IPsecOnly KnownIPv4Seal)
    (originalIP : body.originalHeader = source.body.originalHeader)
    (originalEthernet : body.originalEthernet = source.body.originalEthernet)
    (active : Option PacketPolicy.Packet) (hidden : List (Option PacketPolicy.Packet))
    (coherent : body.HeadersCoherent active hidden) :
    networkLength body = body.visibleHeader.map (fun _ =>
      (encodeBody codec source source.application body active hidden).length) ∧
    source.application.length ≤ (encodeBody codec source source.application body active hidden).length := by
  induction body generalizing active hidden with
  | datagram nominal =>
    have sourceBody := source_IP_body_from_original source decoded nominal originalIP
    have width := (forwarded_network_header_matches source nominal (active.getD nominal)
      sourceBody decoded coherent.1).1
    have fields := decoded
    rw [Datagram.Decoded, sourceBody] at fields
    have length : (encodeBody codec source source.application (.datagram nominal) active hidden).length =
        source.Raw.length := by
      simp only [encodeBody, List.length_append, leafNetwork, width, Datagram.Raw, Datagram.Data]
      omega
    rw [length]
    exact ⟨fields.2.1, by simp only [Datagram.Raw, Datagram.Data, List.length_append]; omega⟩
  | ethernet header =>
    simp [networkLength, Body.visibleHeader, encodeBody]
  | ipsec association contents ih =>
    obtain ⟨known, contentsShape, visible⟩ := shape
    obtain ⟨identity, inner, rest, sameHidden, contentsCoherent⟩ := coherent
    subst hidden
    have recurse := ih contentsShape originalIP originalEthernet inner rest contentsCoherent
    let encodedContents := encodeBody codec source source.application contents inner rest
    let parameters := codec.parameters association
    let protectedBytes := encodeESP codec.primitive (codec.key association)
      association.association parameters.sequence parameters.iv encodedContents (nextHeader contents)
    have headerSize := known_outer_header_size association known active identity protectedBytes.length
    have innerLength : networkLength contents = some encodedContents.length := by
      rw [recurse.1]
      cases value : contents.visibleHeader with
      | none => simp [value] at visible
      | some header => rfl
    have protectedLength := encoded_ESP_length codec.primitive (codec.key association)
      association.association parameters.sequence parameters.iv encodedContents (nextHeader contents) parameters.ivLength
    have length : (encodeBody codec source source.application (.ipsec association contents)
        active (inner :: rest)).length =
          PacketLength.alignedWireLength 4 2 52 encodedContents.length := by
      change (encodeNetworkHeader (active.getD (outerHeader association.sender association.receiver "esp" 0 0))
        protectedBytes.length 0 0 ++ protectedBytes).length = _
      rw [List.length_append, headerSize.2, protectedLength]
      simp only [PacketLength.alignedWireLength]
      omega
    rw [length]
    refine ⟨?_, recurse.2.trans (ESP_network_length_at_least_inner encodedContents.length)⟩
    simp only [networkLength, innerLength, Option.map_some, Body.visibleHeader]
  | macsec association contents ih => exact False.elim shape
  | carrier endpoint contents ih => exact False.elim shape


end TDN.IPsecFrameEncoding
