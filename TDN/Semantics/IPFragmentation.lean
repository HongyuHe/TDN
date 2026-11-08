import TDN.Semantics.PlannedFragmentation
import TDN.Semantics.IPv4FragmentEncoding
import TDN.Semantics.IPv6FragmentEncoding
import TDN.Semantics.SourceHeaderEncoding
import TDN.Semantics.WholePacketEmission

namespace TDN.PacketSource

def fragmentHeaderSize (packet : PacketPolicy.Packet) : Nat :=
  if packet.source < 2^32 then 4 * packet.ipv4HeaderWords else 48

def fragmentCapacity (packet : PacketPolicy.Packet) (mtu : Nat) : Nat :=
  8 * ((mtu - fragmentHeaderSize packet) / 8)

def encodeIPFragmentHeader (packet : PacketPolicy.Packet) (identity : Nat) : FragmentHeaderEncoder :=
  fun offset data more =>
    if packet.source < 2^32 then
      encodeIPv4Header packet data.length identity (ipv4FragmentFlags offset more)
    else encodeIPv6FragmentHeader packet data.length offset more identity

lemma fragment_capacity_bounds (packet : PacketPolicy.Packet) (mtu : Nat)
    (network : NetworkTemplate packet) (minimum : 1280 ≤ mtu) :
    0 < fragmentCapacity packet mtu ∧ fragmentCapacity packet mtu % 8 = 0 ∧
    fragmentHeaderSize packet + fragmentCapacity packet mtu ≤ mtu := by
  have headerBound : fragmentHeaderSize packet ≤ 60 := by
    rcases network with ipv4 | ipv6
    · simp only [fragmentHeaderSize, ipv4.1, ↓reduceIte]
      have words := ipv4.2.2.2
      omega
    · have notIPv4 : ¬ packet.source < 2^32 := by have source := ipv6.1; omega
      simp only [fragmentHeaderSize, notIPv4, ↓reduceIte]
      decide
  unfold fragmentCapacity
  refine ⟨by omega, by omega, by omega⟩

theorem encoded_IP_fragment_is_valid (packet : PacketPolicy.Packet)
    (total capacity mtu identity : Nat) (fragment : Fragment)
    (network : NetworkTemplate packet) (representable : HeaderRepresentable packet)
    (protocolValue : ∃ number, number < 256 ∧ protocolNumber packet.protocol = some number)
    (identifier : identity < 65536) (length : networkHeaderSize packet + total ≤ networkProtocolLimit packet)
    (capacityBound : fragmentHeaderSize packet + capacity ≤ mtu)
    (mtuBound : mtu < networkProtocolLimit packet)
    (facts : FragmentPlanFacts (encodeIPFragmentHeader packet identity) total capacity fragment) :
    fragment.MtuBytes (.datagram packet) ≤ mtu ∧
    if packet.source < 2^32 then fragment.IPv4Fields packet identity ∧
      field fragment.networkHeader 6 2 / 16384 % 2 = 0
    else fragment.IPv6Fields packet identity := by
  have inRange := facts.inRange
  have dataBound := facts.dataBound
  have offsetAligned := facts.offsetAligned
  have dataAligned := facts.dataAligned
  have moreExact := facts.moreExact
  have generated := facts.headerGenerated
  rcases fragment with ⟨header, data, offset, more⟩
  dsimp only at generated inRange dataBound offsetAligned dataAligned moreExact ⊢
  subst header
  obtain ⟨number, numberBound, protocol⟩ := protocolValue
  by_cases ipv4 : packet.source < 2^32
  · have parts : packet.destination < 2^32 ∧ 5 ≤ packet.ipv4HeaderWords ∧
        packet.ipv4HeaderWords ≤ 15 := by
      rcases network with first | second
      · exact first.2
      · have source := second.1
        omega
    have totalBound : 4 * packet.ipv4HeaderWords + total ≤ 65535 := by
      simpa only [networkHeaderSize, networkProtocolLimit, ipv4, ↓reduceIte] using length
    have capacityFits : 4 * packet.ipv4HeaderWords + data.length ≤ mtu := by
      simp only [fragmentHeaderSize, ipv4, ↓reduceIte] at capacityBound
      omega
    simp only [encodeIPFragmentHeader, ipv4, ↓reduceIte]
    refine ⟨?_, encoded_IPv4_fragment_fields packet identity offset data more ipv4 parts.1
      parts.2.1 parts.2.2 (by omega) (by have hop := representable.1; omega)
      number protocol numberBound identifier (by omega) offsetAligned dataAligned⟩
    change (encodeIPv4Header packet data.length identity (ipv4FragmentFlags offset more) ++ data).length ≤ mtu
    rw [List.length_append, encoded_IPv4_header_length packet _ _ _ parts.2.1]
    exact capacityFits
  · have parts : 2^128 ≤ packet.source ∧ packet.source < 2^129 ∧
        2^128 ≤ packet.destination ∧ packet.destination < 2^129 ∧ packet.ipv4HeaderWords = 0 := by
      rcases network with first | second
      · exact False.elim (ipv4 first.1)
      · exact second
    have totalBound : 40 + total ≤ 65575 := by
      simpa only [networkHeaderSize, networkProtocolLimit, ipv4, ↓reduceIte] using length
    have mtuLimit : mtu < 65575 := by
      simpa only [networkProtocolLimit, ipv4, ↓reduceIte] using mtuBound
    have capacityFits : 48 + data.length ≤ mtu := by
      simp only [fragmentHeaderSize, ipv4, ↓reduceIte] at capacityBound
      omega
    have position : offset + fragmentMoreBit more < 65536 := by
      cases more <;> simp [fragmentMoreBit] at moreExact ⊢ <;> omega
    have nextHeader := representable.2.1 (by omega)
    have nextBound : packet.ipv6NextHeader < 256 := by
      rw [protocol] at nextHeader
      have equal := Option.some.inj nextHeader
      omega
    simp only [encodeIPFragmentHeader, ipv4, ↓reduceIte]
    refine ⟨?_, encoded_IPv6_fragment_fields packet data offset identity more parts.1 parts.2.1
      parts.2.2.1 parts.2.2.2.1 (by omega) position offsetAligned dataAligned (by omega)
      (representable.2.1 (by omega)) nextBound⟩
    change (encodeIPv6FragmentHeader packet data.length offset more identity ++ data).length ≤ mtu
    rw [List.length_append, encoded_IPv6_fragment_header_length]
    exact capacityFits

def Datagram.fragmentIP (datagram : Datagram) (packet : PacketPolicy.Packet)
    (identity mtu : Nat) : Datagram :=
  if datagram.MtuBytes ≤ mtu then datagram.asWhole
  else datagram.withPlannedFragments (encodeIPFragmentHeader packet identity) (fragmentCapacity packet mtu)

theorem Datagram.fragment_IP_reassembles (datagram : Datagram) (packet : PacketPolicy.Packet)
    (identity mtu : Nat) (body : datagram.body = .datagram packet)
    (decoded : datagram.Decoded) (network : NetworkTemplate packet)
    (representable : HeaderRepresentable packet)
    (protocol : ∃ number, number < 256 ∧ protocolNumber packet.protocol = some number)
    (identifier : identity < 65536) (headerLength : datagram.networkHeader.length = networkHeaderSize packet)
    (length : datagram.Raw.length ≤ networkProtocolLimit packet) (minimum : 1280 ≤ mtu) :
    (datagram.fragmentIP packet identity mtu).Reassembles mtu := by
  unfold Datagram.fragmentIP
  split
  next fits => exact datagram.whole_packet_reassembles mtu decoded fits
  next oversized =>
    have mtuOversized : mtu < datagram.Raw.length := by
      simp only [Datagram.MtuBytes, body] at oversized
      omega
    obtain ⟨room, aligned, capacityBound⟩ := fragment_capacity_bounds packet mtu network minimum
    have size : networkHeaderSize packet + datagram.Data.length = datagram.Raw.length := by
      simp only [Datagram.Raw, List.length_append, headerLength]
    have capacityOversized : fragmentCapacity packet mtu < datagram.Data.length := by
      have headerComparison : networkHeaderSize packet ≤ fragmentHeaderSize packet := by
        unfold networkHeaderSize fragmentHeaderSize
        split <;> omega
      omega
    apply datagram.planned_fragments_reassemble packet _ _ _ identity body room aligned capacityOversized
    intro fragment facts
    exact encoded_IP_fragment_is_valid packet _ _ _ identity fragment network representable protocol
      identifier (by omega) capacityBound (by omega) facts

theorem Datagram.fragment_IP_reassembles_from_header (datagram : Datagram) (packet : PacketPolicy.Packet)
    (identity mtu : Nat) (body : datagram.body = .datagram packet)
    (unfragmented : datagram.UnfragmentedHeader) (network : NetworkTemplate packet)
    (representable : HeaderRepresentable packet)
    (protocol : ∃ number, number < 256 ∧ protocolNumber packet.protocol = some number)
    (identifier : identity < 65536) (headerLength : datagram.networkHeader.length = networkHeaderSize packet)
    (length : datagram.Raw.length ≤ networkProtocolLimit packet) (minimum : 1280 ≤ mtu) :
    (datagram.fragmentIP packet identity mtu).Reassembles mtu := by
  unfold Datagram.fragmentIP
  split
  next fits => exact datagram.whole_packet_reassembles_from_header mtu unfragmented fits
  next oversized =>
    have mtuOversized : mtu < datagram.Raw.length := by
      simp only [Datagram.MtuBytes, body] at oversized
      omega
    obtain ⟨room, aligned, capacityBound⟩ := fragment_capacity_bounds packet mtu network minimum
    have size : networkHeaderSize packet + datagram.Data.length = datagram.Raw.length := by
      simp only [Datagram.Raw, List.length_append, headerLength]
    have capacityOversized : fragmentCapacity packet mtu < datagram.Data.length := by
      have headerComparison : networkHeaderSize packet ≤ fragmentHeaderSize packet := by
        unfold networkHeaderSize fragmentHeaderSize
        split <;> omega
      omega
    apply datagram.planned_fragments_reassemble packet _ _ _ identity body room aligned capacityOversized
    intro fragment facts
    exact encoded_IP_fragment_is_valid packet _ _ _ identity fragment network representable protocol
      identifier (by omega) capacityBound (by omega) facts

end TDN.PacketSource
