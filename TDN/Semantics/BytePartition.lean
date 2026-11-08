import TDN.Semantics.Fragmentation

namespace TDN.Fragmentation

def bytePartition {Byte : Type} : Nat → Nat → List Byte → List (List Byte)
  | 0, _, bytes => [bytes]
  | fuel + 1, capacity, bytes =>
      if bytes.length ≤ capacity then [bytes]
      else bytes.take capacity :: bytePartition fuel capacity (bytes.drop capacity)

lemma byte_partition_nonempty {Byte : Type} (fuel capacity : Nat) (bytes : List Byte) :
    bytePartition fuel capacity bytes ≠ [] := by
  cases fuel with
  | zero => simp [bytePartition]
  | succ fuel =>
    simp only [bytePartition]
    split <;> simp

lemma byte_partition_restores_bytes {Byte : Type} (fuel capacity : Nat) (bytes : List Byte) :
    (bytePartition fuel capacity bytes).flatten = bytes := by
  induction fuel generalizing bytes with
  | zero => simp [bytePartition]
  | succ fuel ih =>
    simp only [bytePartition]
    split
    · simp
    · simp only [List.flatten_cons, ih, List.take_append_drop]

lemma byte_partition_piece_bound {Byte : Type} (fuel capacity : Nat) (bytes : List Byte)
    (room : 0 < capacity) (enough : bytes.length ≤ fuel) :
    ∀ piece ∈ bytePartition fuel capacity bytes, piece.length ≤ capacity := by
  induction fuel generalizing bytes with
  | zero =>
    intro piece member
    have empty : bytes = [] := List.length_eq_zero_iff.mp (by omega)
    simp only [bytePartition, List.mem_singleton] at member
    subst piece
    simp [empty]
  | succ fuel ih =>
    intro piece member
    simp only [bytePartition] at member
    split at member
    next fits =>
      have same := List.mem_singleton.mp member
      subst piece
      exact fits
    next oversized =>
      rcases List.mem_cons.mp member with same | tail
      · subst piece
        exact (List.length_take_le ..).trans (Nat.le_refl _)
      · apply ih (bytes.drop capacity) _ piece tail
        simp only [List.length_drop]
        omega


inductive BoundedPartition {Byte : Type} (capacity : Nat) :
    List Byte → List (List Byte) → Prop where
  | last (bytes : List Byte) (fits : bytes.length ≤ capacity) :
      BoundedPartition capacity bytes [bytes]
  | more (first rest : List Byte) (tail : List (List Byte))
      (full : first.length = capacity) (nonempty : rest ≠ [])
      (partition : BoundedPartition capacity rest tail) :
      BoundedPartition capacity (first ++ rest) (first :: tail)

theorem byte_partition_is_bounded {Byte : Type} (fuel capacity : Nat) (bytes : List Byte)
    (room : 0 < capacity) (enough : bytes.length ≤ fuel) :
    BoundedPartition capacity bytes (bytePartition fuel capacity bytes) := by
  induction fuel generalizing bytes with
  | zero =>
    have empty : bytes = [] := List.length_eq_zero_iff.mp (by omega)
    subst bytes
    exact .last [] (by simp)
  | succ fuel ih =>
    simp only [bytePartition]
    split
    next fits => exact .last bytes fits
    next oversized =>
      have prefixLength : (bytes.take capacity).length = capacity := by
        simp only [List.length_take]
        omega
      have tailLength : (bytes.drop capacity).length ≤ fuel := by
        simp only [List.length_drop]
        omega
      have tailNonempty : bytes.drop capacity ≠ [] := by
        intro empty
        have length : (bytes.drop capacity).length = bytes.length - capacity := List.length_drop
        rw [empty] at length
        simp only [List.length_nil] at length
        omega
      have result := BoundedPartition.more (bytes.take capacity) (bytes.drop capacity)
        (bytePartition fuel capacity (bytes.drop capacity)) prefixLength tailNonempty
        (ih _ tailLength)
      simpa only [List.take_append_drop] using result

end TDN.Fragmentation
