import TDN.Models.RawPacketDecodeAndHooks
import Lean.Elab.Tactic.Omega

namespace TDN.PacketSource

lemma two_byte_field (bytes : List UInt8) (offset : Nat) (available : offset + 2 ≤ bytes.length) :
    field bytes offset 2 =
      ((bytes[offset]?.getD 0).toNat * 256 + (bytes[offset + 1]?.getD 0).toNat) := by
  have enough : 2 ≤ (bytes.drop offset).length := by simp only [List.length_drop]; omega
  have atDrop : field bytes offset 2 =
      ((((bytes.drop offset)[0]?).getD 0).toNat * 256 +
        (((bytes.drop offset)[1]?).getD 0).toNat) := by
    unfold field unsigned
    generalize bytes.drop offset = remaining at *
    cases remaining with
    | nil => simp at enough
    | cons first tail =>
      cases tail with
      | nil => simp at enough
      | cons second tail => simp
  simpa only [List.getElem?_drop, Nat.add_zero] using atDrop

end TDN.PacketSource

namespace TDN.PacketProcessing

lemma decoded_IPv4_UDP_framing (raw : RawPacket) (packet : PacketPolicy.Packet)
    (complete : raw.Complete packet) (ipv4 : packet.source < 2^32)
    (udp : packet.protocol = "udp") :
    packet.destination < 2^32 ∧ 5 ≤ packet.ipv4HeaderWords ∧ packet.ipv4HeaderWords ≤ 15 ∧
    packet.ipv4FragmentOffset = some 0 ∧
    ∃ bytes, packet.payloadBytes = some bytes ∧
      packet.networkBytes = some (4 * packet.ipv4HeaderWords + 8 + bytes.length) := by
  cases raw with
  | ethernet header rawHeader payload =>
    have protocol : packet.protocol = "ethernet" := complete.1.1
    simp [udp] at protocol
  | ip network transport payload =>
    obtain ⟨decoded, noFragments⟩ := complete
    obtain ⟨body, total, networkMatches, offset, transportMatches⟩ := decoded
    have bodyEq : packet.payloadBytes = some payload := by simpa [udp] using body
    have transportLength : transport.length = 8 := by
      simp [PacketSource.TransportHeaderMatches, udp] at transportMatches
      exact transportMatches.1
    rcases networkMatches with v4 | v6
    · obtain ⟨_, destination, lower, upper, _, _, words, _⟩ := v4
      have bounds : 5 ≤ packet.ipv4HeaderWords ∧ packet.ipv4HeaderWords ≤ 15 := by omega
      have decodedOffset : packet.IPv4FragmentOffsetDecoded network := by
        simpa [udp] using offset ipv4
      have noOffset := (noFragments ipv4).1
      rw [PacketSource.two_byte_field network 6 (by omega)] at noOffset
      have offsetZero : packet.ipv4FragmentOffset = some 0 := by
        rw [decodedOffset.2, noOffset]
      refine ⟨destination, bounds.1, bounds.2, offsetZero, payload, bodyEq, ?_⟩
      simpa only [words, transportLength] using total
    · have large := v6.1
      omega

lemma eligible_IKE_has_framing (raw : RawPacket) (packet : PacketPolicy.Packet)
    (complete : raw.Complete packet) (ipv4 : packet.source < 2^32)
    (ike : packet.protocol = "udp" ∧
      (((packet.sourcePort = 500 ∨ packet.destinationPort = 500) ∧
          PacketPolicy.IKEHeader (packet.payloadBytes.getD [])) ∨
        ((packet.sourcePort = 4500 ∨ packet.destinationPort = 4500) ∧
          (packet.payloadBytes.getD []).take 4 = [0, 0, 0, 0] ∧
          PacketPolicy.IKEHeader ((packet.payloadBytes.getD []).drop 4)))) :
    packet.IPsecUDPFramingWithOptions ∨ packet.IPsecUDPReplyFramingWithOptions := by
  obtain ⟨destination, lower, upper, offset, bytes, payload, total⟩ :=
    decoded_IPv4_UDP_framing raw packet complete ipv4 ike.1
  rcases ike.2 with ⟨iface | iface, header⟩ | ⟨iface | iface, zero, header⟩
  · right
    refine ⟨ipv4, destination, lower, upper, offset, ike.1, bytes, payload, total,
      Or.inl ⟨iface, ?_⟩⟩
    simpa only [payload, Option.getD_some] using header
  · left
    refine ⟨ipv4, destination, lower, upper, offset, ike.1, bytes, payload, total,
      Or.inl ⟨iface, ?_⟩⟩
    simpa only [payload, Option.getD_some] using header
  · right
    have size : 8 ≤ bytes.length := by
      have headerSize := header.1
      simp only [payload, Option.getD_some, List.length_drop] at headerSize
      omega
    refine ⟨ipv4, destination, lower, upper, offset, ike.1, bytes, payload, total,
      Or.inr ⟨iface, size, Or.inr ⟨?_, ?_⟩⟩⟩
    · simpa only [payload, Option.getD_some] using zero
    · simpa only [payload, Option.getD_some] using header
  · left
    have size : 8 ≤ bytes.length := by
      have headerSize := header.1
      simp only [payload, Option.getD_some, List.length_drop] at headerSize
      omega
    refine ⟨ipv4, destination, lower, upper, offset, ike.1, bytes, payload, total,
      Or.inr ⟨iface, size, Or.inr ⟨?_, ?_⟩⟩⟩
    · simpa only [payload, Option.getD_some] using zero
    · simpa only [payload, Option.getD_some] using header

lemma eligible_UDPESP_has_framing (raw : RawPacket) (packet : PacketPolicy.Packet)
    (complete : raw.Complete packet) (ipv4 : packet.source < 2^32)
    (esp : packet.protocol = "udp" ∧ (packet.sourcePort = 4500 ∨ packet.destinationPort = 4500) ∧
      8 ≤ (packet.payloadBytes.getD []).length ∧
      (packet.payloadBytes.getD []).take 4 ≠ [0, 0, 0, 0]) :
    packet.IPsecUDPFramingWithOptions ∨ packet.IPsecUDPReplyFramingWithOptions := by
  obtain ⟨destination, lower, upper, offset, bytes, payload, total⟩ :=
    decoded_IPv4_UDP_framing raw packet complete ipv4 esp.1
  have size : 8 ≤ bytes.length := by simpa [payload] using esp.2.2.1
  have nonzero : bytes.take 4 ≠ [0, 0, 0, 0] := by simpa [payload] using esp.2.2.2
  rcases esp.2.1 with iface | iface
  · exact Or.inr ⟨ipv4, destination, lower, upper, offset, esp.1, bytes, payload, total,
      Or.inr ⟨iface, size, Or.inl nonzero⟩⟩
  · exact Or.inl ⟨ipv4, destination, lower, upper, offset, esp.1, bytes, payload, total,
      Or.inr ⟨iface, size, Or.inl nonzero⟩⟩

end TDN.PacketProcessing
