import TDN.Semantics.DecodedHeaderProperties

namespace TDN.LayeredFrame

lemma HeaderIdentity.actual_is_nominal_with_hop {actual nominal : PacketPolicy.Packet}
    (identity : HeaderIdentity actual nominal) :
    actual = { nominal with hopLimit := actual.hopLimit } := by
  have same := congrArg (fun packet : PacketPolicy.Packet =>
    { packet with hopLimit := actual.hopLimit }) identity.1
  exact same

end TDN.LayeredFrame

namespace TDN.PacketSource
open LayeredFrame

def forwardedNetworkHeader (datagram : Datagram) (nominal actual : PacketPolicy.Packet) :
    List UInt8 :=
  if actual = nominal then datagram.networkHeader
  else encodeNetworkHeader actual datagram.Data.length
    (field datagram.networkHeader 4 2) (field datagram.networkHeader 6 2)

lemma forwarded_network_header_matches (datagram : Datagram) (nominal actual : PacketPolicy.Packet)
    (body : datagram.body = .datagram nominal) (decoded : datagram.Decoded)
    (identity : HeaderIdentity actual nominal) :
    (forwardedNetworkHeader datagram nominal actual).length = datagram.networkHeader.length ∧
      NetworkHeaderMatches actual (forwardedNetworkHeader datagram nominal actual) datagram.Data.length := by
  have properties := decoded_IP_header_properties datagram nominal body decoded
  have same := identity.actual_is_nominal_with_hop
  have network : NetworkTemplate actual := by
    rw [same]
    exact properties.1
  have representable : HeaderRepresentable actual := by
    refine ⟨identity.2, ?_, ?_⟩
    · rw [same]
      exact properties.2.2.1.2.1
    · rw [same]
      exact properties.2.2.1.2.2
  have protocol : ∃ number, protocolNumber actual.protocol = some number ∧ number < 256 := by
    rw [same]
    exact properties.2.2.2.1
  have size : networkHeaderSize actual + datagram.Data.length ≤ networkProtocolLimit actual := by
    rw [same]
    change networkHeaderSize nominal + datagram.Data.length ≤ networkProtocolLimit nominal
    rw [← properties.2.1]
    simpa only [Datagram.Raw, List.length_append] using properties.2.2.2.2
  have width : networkHeaderSize actual = datagram.networkHeader.length := by
    rw [same]
    exact properties.2.1.symm
  unfold forwardedNetworkHeader
  split
  next equal =>
    subst actual
    rw [Datagram.Decoded, body] at decoded
    exact ⟨rfl, decoded.2.2.1⟩
  next different =>
    have encoded := source_network_header_matches actual datagram.Data.length
      (field datagram.networkHeader 4 2) (field datagram.networkHeader 6 2)
      network representable protocol size
    exact ⟨encoded.1.trans width, encoded.2⟩

lemma forwarded_transport_header_matches (datagram : Datagram) (nominal actual : PacketPolicy.Packet)
    (body : datagram.body = .datagram nominal) (decoded : datagram.Decoded)
    (identity : HeaderIdentity actual nominal) :
    TransportHeaderMatches actual datagram.transportHeader datagram.application := by
  rw [identity.actual_is_nominal_with_hop]
  change TransportHeaderMatches nominal datagram.transportHeader datagram.application
  rw [Datagram.Decoded, body] at decoded
  exact decoded.2.2.2.1

lemma initial_forwarded_network_bytes (datagram : Datagram) (nominal : PacketPolicy.Packet) :
    forwardedNetworkHeader datagram nominal nominal = datagram.networkHeader := by
  simp [forwardedNetworkHeader]

end TDN.PacketSource
