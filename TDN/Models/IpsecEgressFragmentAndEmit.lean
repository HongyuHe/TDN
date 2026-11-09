import TDN.Models.PerStageMtuInvariants
import TDN.Models.Ipv4AndIpv6FragmentBuilder

namespace TDN.IPsecFrameEncoding
open PacketSource LayeredFrame ESPWire


def protectedData {Key : Type} (codec : Codec Key) (source : Datagram)
    (association : DataPlaneForwarding.TunnelSAStamp) (contents : Body) (hidden : List (Option PacketPolicy.Packet)) : List UInt8 :=
  let parameters := codec.parameters association
  encodeESP codec.primitive (codec.key association) association.association parameters.sequence parameters.iv
    (encodeBody codec source source.application contents (hidden.head?.getD none) (hidden.drop 1))
    (nextHeader contents)


def bareEmission {Key : Type} (codec : Codec Key) (source : Datagram) (frame : Frame) : Datagram :=
  match frame.body with
  | .datagram nominal =>
      let actual := frame.activeHeader.getD nominal
      let network := leafNetwork source nominal actual
      { body := .datagram { actual with networkBytes := some (network.length + source.transportHeader.length + source.application.length) },
        networkHeader := network, transportHeader := source.transportHeader,
        application := source.application, fragments := [] }
  | .ipsec association contents =>
      let actual := frame.activeHeader.getD (outerHeader association.sender association.receiver "esp" 0 0)
      let protectedBytes := protectedData codec source association contents frame.hiddenHeaders
      let network := encodeNetworkHeader actual protectedBytes.length 0 0
      { body := .datagram { actual with networkBytes := some (network.length + protectedBytes.length) },
        networkHeader := network, transportHeader := [], application := protectedBytes, fragments := [] }
  | .ethernet header =>
      { body := .ethernet header, networkHeader := source.networkHeader, transportHeader := [],
        application := source.application, fragments := [] }
  | .macsec _ _ | .carrier _ _ => source


def wireEmission {Key : Type} (codec : Codec Key) (source : Datagram) (frame : Frame) (mtu : Nat) : Datagram :=
  let bare := bareEmission codec source frame
  match bare.body with
  | .datagram header => bare.fragmentIP header 0 mtu
  | _ => bare.asWhole

lemma bare_emission_raw {Key : Type} (codec : Codec Key) (source : Datagram)
    (frame : Frame) (shape : frame.body.IPsecOnly KnownIPv4Seal) :
    (bareEmission codec source frame).Raw = encodeFrame codec source source.application frame := by
  cases body : frame.body <;>
    simp_all only [bareEmission, Datagram.Raw, Datagram.Data, encodeFrame, encodeBody,
      protectedData, List.append_assoc, List.nil_append, Body.IPsecOnly]

lemma wire_emission_raw {Key : Type} (codec : Codec Key) (source : Datagram)
    (frame : Frame) (mtu : Nat) :
    (wireEmission codec source frame mtu).Raw = (bareEmission codec source frame).Raw := by
  dsimp only [wireEmission]
  split
  · unfold Datagram.fragmentIP
    split <;> rfl
  · rfl

lemma wire_emission_body {Key : Type} (codec : Codec Key) (source : Datagram)
    (frame : Frame) (mtu : Nat) :
    (wireEmission codec source frame mtu).body = (bareEmission codec source frame).body := by
  dsimp only [wireEmission]
  split
  · unfold Datagram.fragmentIP
    split <;> rfl
  · rfl

lemma wire_emission_network {Key : Type} (codec : Codec Key) (source : Datagram)
    (frame : Frame) (mtu : Nat) :
    (wireEmission codec source frame mtu).networkHeader = (bareEmission codec source frame).networkHeader ∧
      (wireEmission codec source frame mtu).Data = (bareEmission codec source frame).Data := by
  dsimp only [wireEmission]
  split
  · unfold Datagram.fragmentIP
    split <;> exact ⟨rfl, rfl⟩
  · exact ⟨rfl, rfl⟩

lemma wire_Ethernet_size {Key : Type} (codec : Codec Key) (source : Datagram)
    (frame : Frame) (header : EthernetHeader) (body : frame.body = .ethernet header) (mtu : Nat) :
    (wireEmission codec source frame mtu).MtuBytes = source.application.length := by
  simp only [wireEmission, bareEmission, body, Datagram.MtuBytes, Datagram.asWhole, Datagram.Data,
    List.nil_append]

lemma wire_fitting_fragment_count {Key : Type} (codec : Codec Key) (source : Datagram)
    (frame : Frame) (mtu : Nat)
    (fits : (wireEmission codec source frame mtu).MtuBytes ≤ mtu) :
    (wireEmission codec source frame mtu).fragments.length = 1 := by
  dsimp only [wireEmission] at fits ⊢
  split
  next header body =>
    rw [body] at fits
    unfold Datagram.fragmentIP at fits ⊢
    split
    · rfl
    next missed =>
      simp only [if_neg missed] at fits
      have sameSize : ((bareEmission codec source frame).withPlannedFragments
          (encodeIPFragmentHeader header 0) (fragmentCapacity header mtu)).MtuBytes =
          (bareEmission codec source frame).MtuBytes := rfl
      rw [sameSize] at fits
      contradiction
  next => rfl

lemma forwarded_header_unfragmented (source : Datagram) (nominal actual : PacketPolicy.Packet)
    (body : source.body = .datagram nominal) (decoded : source.Decoded)
    (identity : HeaderIdentity actual nominal) (ipv4 : actual.source < 2^32) :
    field (forwardedNetworkHeader source nominal actual) 6 2 % 8192 = 0 ∧
    field (forwardedNetworkHeader source nominal actual) 6 2 / 8192 % 2 = 0 := by
  have initial := source.decoded_header_is_unfragmented decoded
  rw [Datagram.UnfragmentedHeader, body] at initial
  have nominalIPv4 : nominal.source < 2^32 := by rw [← identity.source]; exact ipv4
  have original := initial nominalIPv4
  unfold forwardedNetworkHeader
  split
  · exact original
  · unfold encodeNetworkHeader
    rw [if_pos ipv4, encoded_IPv4_flags _ _ _ _ (field_bound source.networkHeader 6 2)]
    exact original

lemma bare_emission_IP_properties {Key : Type} (codec : Codec Key) (source : Datagram)
    (decoded : source.Decoded) (frame : Frame)
    (shape : frame.body.IPsecOnly KnownIPv4Seal)
    (originalIP : frame.body.originalHeader = source.body.originalHeader)
    (originalEthernet : frame.body.originalEthernet = source.body.originalEthernet)
    (coherent : frame.HeadersCoherent) (limit : Nat → Nat)
    (budget : MultiProtocolForwarding.BodySizeBudget limit frame.body)
    (actual : PacketPolicy.Packet) (visible : frame.visibleHeader = some actual) :
    (bareEmission codec source frame).body =
      .datagram { actual with networkBytes := some (bareEmission codec source frame).Raw.length } ∧
    NetworkHeaderMatches actual (bareEmission codec source frame).networkHeader
      (bareEmission codec source frame).Data.length ∧
    (bareEmission codec source frame).UnfragmentedHeader := by
  obtain ⟨nominal, nominalVisible, identity⟩ := frame.coherent_visible coherent actual visible
  cases body : frame.body with
  | datagram header =>
    have same : nominal = header := by
      simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible.symm
    subst nominal
    have sourceBody := source_IP_body_from_original source decoded header (by simpa only [body, Body.originalHeader] using originalIP)
    have actualSame : frame.activeHeader.getD header = actual := by
      simpa only [Frame.visibleHeader, body, Body.visibleHeader, Option.some.injEq] using visible
    have fields := forwarded_network_header_matches source header actual sourceBody decoded identity
    simp only [bareEmission, body, actualSame, Datagram.Raw, Datagram.Data, List.length_append]
    refine ⟨by simp only [Nat.add_assoc], ?_, ?_⟩
    · simpa only [leafNetwork, Datagram.Data, List.length_append] using fields.2
    · exact fun ipv4 => forwarded_header_unfragmented source header actual sourceBody decoded identity ipv4
  | ethernet header => simp [Body.visibleHeader, body] at nominalVisible
  | ipsec association contents =>
    have shapeAt : KnownIPv4Seal association ∧ contents.IPsecOnly KnownIPv4Seal ∧
        contents.visibleHeader.isSome = true := by simpa only [body, Body.IPsecOnly] using shape
    obtain ⟨known, contentsShape, isIP⟩ := shapeAt
    have same : nominal = outerHeader association.sender association.receiver "esp" 0 0 :=
      by simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible.symm
    subst nominal
    have actualSame : frame.activeHeader.getD (outerHeader association.sender association.receiver "esp" 0 0) = actual := by
      simpa only [Frame.visibleHeader, body, Body.visibleHeader, Option.some.injEq] using visible
    have senderBound : association.sender < 2^32 := known.1
    have actualIPv4 : actual.source < 2^32 := by rw [identity.source]; exact known.1
    have template : NetworkTemplate actual := by
      rw [identity.actual_is_nominal_with_hop]
      exact Or.inl ⟨known.1, known.2.1, by
          simp only [outerHeader, InternetAddresses.headerWords]
          split <;> omega,
        by
          simp only [outerHeader, InternetAddresses.headerWords]
          split <;> omega⟩
    have representable : HeaderRepresentable actual := by
      rw [identity.actual_is_nominal_with_hop]
      exact ⟨identity.2, by simp [outerHeader]; omega, by simp [outerHeader]⟩
    have protocol : ∃ number, protocolNumber actual.protocol = some number ∧ number < 256 := by
      rw [identity.actual_is_nominal_with_hop]
      exact ⟨50, rfl, by decide⟩
    have length := encoded_body_network_length codec source decoded frame.body shape originalIP
      originalEthernet frame.activeHeader frame.hiddenHeaders coherent
    have outerBudget := budget
    rw [body] at outerBudget
    obtain ⟨_, _, innerBytes, innerLength, innerBound, maximum⟩ := outerBudget
    have serializedLength : (encodeFrame codec source source.application frame).length =
        PacketLength.alignedWireLength 4 2 52 innerBytes := by
      simpa only [encodeFrame, body, networkLength, innerLength, Option.map_some,
        Body.visibleHeader, Option.some.injEq] using length.1.symm
    have serializedBound : (encodeFrame codec source source.application frame).length ≤ 65535 := by
      rw [serializedLength]
      exact (PacketLength.aligned_wire_length_monotone 4 2 52 innerBound).trans maximum
    let protectedBytes := protectedData codec source association contents frame.hiddenHeaders
    have width := known_outer_header_size association known frame.activeHeader
      (by rw [actualSame]; exact identity) protectedBytes.length
    have totalLength : (encodeFrame codec source source.application frame).length =
        20 + protectedBytes.length := by
      rw [← bare_emission_raw codec source frame shape]
      simp only [bareEmission, body, Datagram.Raw, Datagram.Data, List.nil_append, List.length_append]
      change (encodeNetworkHeader
        (frame.activeHeader.getD (outerHeader association.sender association.receiver "esp" 0 0))
        protectedBytes.length 0 0).length + protectedBytes.length = _
      rw [width.2]
    have headerWidth : networkHeaderSize actual = 20 := by rw [← actualSame]; exact width.1
    have size : networkHeaderSize actual + protectedBytes.length ≤ networkProtocolLimit actual := by
      rw [headerWidth]
      simpa only [totalLength, networkProtocolLimit, actualIPv4, ↓reduceIte] using serializedBound
    have fields := source_network_header_matches actual protectedBytes.length 0 0 template representable protocol size
    simp only [bareEmission, body, actualSame, Datagram.Raw, Datagram.Data, List.nil_append,
      List.length_append]
    refine ⟨True.intro, fields.2, ?_⟩
    intro ipv4
    simp only [encodeNetworkHeader, ipv4, ↓reduceIte, encoded_IPv4_flags _ _ _ _ (by decide : 0 < 65536)]
    decide
  | macsec association contents => simp only [body, Body.IPsecOnly] at shape
  | carrier endpoint contents => simp only [body, Body.IPsecOnly] at shape

lemma reachable_visible_representable (source : Datagram) (decoded : source.Decoded)
    (frame : Frame) (shape : frame.body.IPsecOnly KnownIPv4Seal)
    (original : frame.body.originalHeader = source.body.originalHeader)
    (coherent : frame.HeadersCoherent) (actual : PacketPolicy.Packet)
    (visible : frame.visibleHeader = some actual) : HeaderRepresentable actual := by
  obtain ⟨nominal, nominalVisible, identity⟩ := frame.coherent_visible coherent actual visible
  cases body : frame.body with
  | datagram header =>
    have same : nominal = header := by simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible.symm
    subst nominal
    have sourceBody := source_IP_body_from_original source decoded header
      (by simpa only [body, Body.originalHeader] using original)
    have representable := (decoded_IP_header_properties source header sourceBody decoded).2.2.1
    rw [identity.actual_is_nominal_with_hop]
    exact ⟨identity.2, representable.2⟩
  | ipsec association contents =>
    have same : nominal = outerHeader association.sender association.receiver "esp" 0 0 := by
      simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible.symm
    subst nominal
    have allShape : KnownIPv4Seal association ∧ contents.IPsecOnly KnownIPv4Seal ∧
        contents.visibleHeader.isSome = true := by simpa only [body, Body.IPsecOnly] using shape
    have known := allShape.1
    rw [identity.actual_is_nominal_with_hop]
    refine ⟨identity.2, ?_, by simp [outerHeader]⟩
    simp only [outerHeader]
    intro outside
    have source := known.1
    omega
  | ethernet header => simp only [body, Body.visibleHeader] at nominalVisible; cases nominalVisible
  | macsec association contents => simp only [body, Body.IPsecOnly] at shape
  | carrier endpoint contents => simp only [body, Body.IPsecOnly] at shape


theorem wire_IP_reassembles {Key : Type} (codec : Codec Key) (source : Datagram)
    (decoded : source.Decoded) (frame : Frame)
    (shape : frame.body.IPsecOnly KnownIPv4Seal)
    (originalIP : frame.body.originalHeader = source.body.originalHeader)
    (originalEthernet : frame.body.originalEthernet = source.body.originalEthernet)
    (coherent : frame.HeadersCoherent) (limit : Nat → Nat)
    (budget : MultiProtocolForwarding.BodySizeBudget limit frame.body)
    (actual : PacketPolicy.Packet) (visible : frame.visibleHeader = some actual)
    (mtu : Nat) (minimum : 1280 ≤ mtu) : (wireEmission codec source frame mtu).Reassembles mtu := by
  have properties := bare_emission_IP_properties codec source decoded frame shape originalIP originalEthernet
    coherent limit budget actual visible
  have fields := matched_network_header_properties actual (bareEmission codec source frame).networkHeader
    (bareEmission codec source frame).Data.length properties.2.1
  have representable := reachable_visible_representable source decoded frame shape originalIP coherent actual visible
  dsimp only [wireEmission]
  rw [properties.1]
  apply Datagram.fragment_IP_reassembles_from_header _ _ 0 mtu properties.1 properties.2.2
  · exact fields.1
  · exact representable
  · obtain ⟨number, protocol, bound⟩ := fields.2.2.2.1
    exact ⟨number, bound, protocol⟩
  · decide
  · exact fields.2.1
  · simpa only [Datagram.Raw, List.length_append, networkProtocolLimit] using fields.2.2.2.2.1
  · exact minimum

end TDN.IPsecFrameEncoding
