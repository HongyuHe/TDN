import TDN.Models.FragmentOffsetAndLengthPlan

namespace TDN.PacketSource

@[simp] lemma made_fragments_length (encode : FragmentHeaderEncoder) (total offset : Nat)
    (chunks : List (List UInt8)) :
    (makeFragments encode total offset chunks).length = chunks.length := by
  induction chunks generalizing offset with
  | nil => rfl
  | cons bytes rest ih => simp only [makeFragments, List.length_cons, ih]

lemma partition_of_oversized_packet_has_multiple_chunks (capacity : Nat) (bytes : List UInt8)
    (oversized : capacity < bytes.length) :
    1 < (Fragmentation.bytePartition bytes.length capacity bytes).length := by
  cases length : bytes.length with
  | zero => omega
  | succ fuel =>
    rw [Fragmentation.bytePartition, if_neg (by omega)]
    have tail := Fragmentation.byte_partition_nonempty fuel capacity (bytes.drop capacity)
    have positive := List.length_pos_iff.mpr tail
    simp only [List.length_cons]
    omega

def Datagram.withPlannedFragments (datagram : Datagram) (encode : FragmentHeaderEncoder)
    (capacity : Nat) : Datagram :=
  { datagram with
    fragments := makeFragments encode datagram.Data.length 0
      (Fragmentation.bytePartition datagram.Data.length capacity datagram.Data) }

@[simp] lemma Datagram.planned_body (datagram : Datagram) (encode : FragmentHeaderEncoder)
    (capacity : Nat) : (datagram.withPlannedFragments encode capacity).body = datagram.body := rfl

@[simp] lemma Datagram.planned_data (datagram : Datagram) (encode : FragmentHeaderEncoder)
    (capacity : Nat) : (datagram.withPlannedFragments encode capacity).Data = datagram.Data := rfl

@[simp] lemma Datagram.planned_raw (datagram : Datagram) (encode : FragmentHeaderEncoder)
    (capacity : Nat) : (datagram.withPlannedFragments encode capacity).Raw = datagram.Raw := rfl

theorem Datagram.planned_fragments_reassemble (datagram : Datagram)
    (packet : PacketPolicy.Packet) (encode : FragmentHeaderEncoder) (capacity mtu identity : Nat)
    (body : datagram.body = .datagram packet) (room : 0 < capacity)
    (aligned : capacity % 8 = 0) (oversized : capacity < datagram.Data.length)
    (header : ∀ fragment, FragmentPlanFacts encode datagram.Data.length capacity fragment →
      fragment.MtuBytes (.datagram packet) ≤ mtu ∧
      if packet.source < 2^32 then fragment.IPv4Fields packet identity ∧
        field fragment.networkHeader 6 2 / 16384 % 2 = 0
      else fragment.IPv6Fields packet identity) :
    (datagram.withPlannedFragments encode capacity).Reassembles mtu := by
  have partition := Fragmentation.byte_partition_is_bounded datagram.Data.length capacity
    datagram.Data room (Nat.le_refl _)
  have plan := made_fragments_follow_plan encode datagram.Data.length capacity datagram.Data _
    partition aligned 0 (by decide) (by omega)
  refine ⟨made_fragments_are_valid_pieces encode capacity datagram.Data _ partition, ?_, ?_⟩
  · intro fragment member
    have facts := plan fragment member
    exact ⟨facts.moreExact, by simpa only [Datagram.planned_body, body] using (header fragment facts).1⟩
  · have multiple := partition_of_oversized_packet_has_multiple_chunks capacity datagram.Data oversized
    have count : (datagram.withPlannedFragments encode capacity).fragments.length ≠ 1 := by
      change (makeFragments encode datagram.Data.length 0 _).length ≠ 1
      rw [made_fragments_length]
      omega
    simp only [Datagram.planned_body, body, count, ↓reduceIte]
    exact ⟨identity, fun fragment member => (header fragment (plan fragment member)).2⟩

end TDN.PacketSource
