import TDN.Models.BoundedByteChunking
import TDN.Models.EndpointTransmitSpec

namespace TDN.PacketSource

abbrev FragmentHeaderEncoder := Nat → List UInt8 → Bool → List UInt8

def makeFragments (encode : FragmentHeaderEncoder) (total offset : Nat) :
    List (List UInt8) → List Fragment
  | [] => []
  | bytes :: rest =>
      let more := decide (offset + bytes.length < total)
      { networkHeader := encode offset bytes more, data := bytes, offset := offset, more := more } ::
        makeFragments encode total (offset + bytes.length) rest

lemma made_fragments_as_pieces (encode : FragmentHeaderEncoder) (total offset : Nat)
    (chunks : List (List UInt8)) :
    (makeFragments encode total offset chunks).map Fragment.AsPiece =
      Fragmentation.makePieces () offset chunks := by
  induction chunks generalizing offset with
  | nil => rfl
  | cons bytes rest ih => simp only [makeFragments, List.map_cons, Fragmentation.makePieces, ih]; rfl

structure FragmentPlanFacts (encode : FragmentHeaderEncoder) (total capacity : Nat)
    (fragment : Fragment) : Prop where
  offsetAligned : fragment.offset % 8 = 0
  inRange : fragment.offset + fragment.data.length ≤ total
  dataBound : fragment.data.length ≤ capacity
  moreExact : fragment.more = decide (fragment.offset + fragment.data.length < total)
  dataAligned : fragment.more = true → fragment.data.length % 8 = 0
  headerGenerated : fragment.networkHeader = encode fragment.offset fragment.data fragment.more

theorem made_fragments_follow_plan (encode : FragmentHeaderEncoder) (total capacity : Nat)
    (bytes : List UInt8) (chunks : List (List UInt8))
    (partition : Fragmentation.BoundedPartition capacity bytes chunks)
    (capacityAligned : capacity % 8 = 0) (offset : Nat)
    (offsetAligned : offset % 8 = 0) (whole : offset + bytes.length = total) :
    ∀ fragment ∈ makeFragments encode total offset chunks,
      FragmentPlanFacts encode total capacity fragment := by
  induction partition generalizing offset with
  | last bytes fits =>
    intro fragment member
    simp only [makeFragments, List.mem_cons, List.not_mem_nil, or_false] at member
    subst fragment
    refine ⟨offsetAligned, ?_, fits, rfl, ?_, rfl⟩
    · exact Nat.le_of_eq whole
    · intro more
      simp only [whole, Nat.lt_irrefl, decide_false, Bool.false_eq_true] at more
  | more first rest tail full nonempty partition ih =>
    intro fragment member
    simp only [makeFragments, List.mem_cons] at member
    rcases member with same | inTail
    · subst fragment
      refine ⟨offsetAligned, ?_, Nat.le_of_eq full, rfl, ?_, rfl⟩
      · change offset + first.length ≤ total
        simp only [List.length_append] at whole
        omega
      · intro _
        rw [full]
        exact capacityAligned
    · apply ih (offset + first.length) _ _ fragment inTail
      · rw [Nat.add_mod, offsetAligned, full, capacityAligned]
      · simpa only [List.length_append, Nat.add_assoc] using whole

end TDN.PacketSource

namespace TDN.Fragmentation

lemma BoundedPartition.chunks_nonempty {Byte : Type} {capacity : Nat}
    {bytes : List Byte} {chunks : List (List Byte)}
    (partition : BoundedPartition capacity bytes chunks) : chunks ≠ [] := by
  cases partition <;> simp

lemma BoundedPartition.restores_bytes {Byte : Type} {capacity : Nat}
    {bytes : List Byte} {chunks : List (List Byte)}
    (partition : BoundedPartition capacity bytes chunks) : chunks.flatten = bytes := by
  induction partition with
  | last bytes fits => simp
  | more first rest tail full nonempty partition ih => simp [ih]

end TDN.Fragmentation

namespace TDN.PacketSource

theorem made_fragments_are_valid_pieces (encode : FragmentHeaderEncoder) (capacity : Nat)
    (bytes : List UInt8) (chunks : List (List UInt8))
    (partition : Fragmentation.BoundedPartition capacity bytes chunks) :
    Fragmentation.ValidPieces ⟨(), bytes⟩
      ((makeFragments encode bytes.length 0 chunks).map Fragment.AsPiece) := by
  rw [made_fragments_as_pieces]
  exact Fragmentation.arbitrary_partition_is_valid ⟨(), bytes⟩ chunks
    partition.chunks_nonempty partition.restores_bytes

end TDN.PacketSource
