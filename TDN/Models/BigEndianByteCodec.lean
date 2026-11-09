import TDN.Models.EndpointTransmitSpec
import Mathlib.Tactic.Ring

namespace TDN.PacketSource

lemma unsigned_accumulator (bytes : List UInt8) (initial : Nat) :
    bytes.foldl (fun value byte => value * 256 + byte.toNat) initial =
      initial * 256^bytes.length + unsigned bytes := by
  induction bytes generalizing initial with
  | nil => simp [unsigned]
  | cons byte rest ih =>
    simp only [List.foldl_cons, List.length_cons, unsigned]
    rw [ih, ih]
    simp only [Nat.pow_succ]
    ring

lemma unsigned_append (first second : List UInt8) :
    unsigned (first ++ second) = unsigned first * 256^second.length + unsigned second := by
  unfold unsigned
  rw [List.foldl_append]
  exact unsigned_accumulator second _

lemma unsigned_bound (bytes : List UInt8) : unsigned bytes < 256^bytes.length := by
  induction bytes with
  | nil => decide
  | cons byte rest ih =>
    have value : byte.toNat ≤ 255 := by have bound := byte.toNat_lt; omega
    simp only [unsigned, List.foldl_cons, List.length_cons, Nat.zero_mul, Nat.zero_add]
    rw [unsigned_accumulator, Nat.pow_succ]
    have multiple := Nat.mul_le_mul_right (256^rest.length) value
    omega

lemma field_bound (bytes : List UInt8) (offset count : Nat) :
    field bytes offset count < 256^count := by
  have small := unsigned_bound ((bytes.drop offset).take count)
  have length : ((bytes.drop offset).take count).length ≤ count := List.length_take_le _ _
  have power : 256^((bytes.drop offset).take count).length ≤ 256^count :=
    Nat.pow_le_pow_right (by decide) length
  exact small.trans_le power


def encodeUnsigned : Nat → Nat → List UInt8
  | 0, _ => []
  | width + 1, value => encodeUnsigned width (value / 256) ++ [UInt8.ofNat (value % 256)]

@[simp] lemma encodeUnsigned_length (width value : Nat) :
    (encodeUnsigned width value).length = width := by
  induction width generalizing value with
  | zero => rfl
  | succ width ih => simp [encodeUnsigned, ih]

theorem encodeUnsigned_decodes (width value : Nat) (fits : value < 256^width) :
    unsigned (encodeUnsigned width value) = value := by
  induction width generalizing value with
  | zero =>
    have same : value = 0 := by simpa using fits
    subst value
    rfl
  | succ width ih =>
    have smaller : value / 256 < 256^width := by
      apply (Nat.div_lt_iff_lt_mul (by decide : 0 < 256)).2
      simpa only [Nat.pow_succ, Nat.mul_comm] using fits
    rw [encodeUnsigned, unsigned_append, ih _ smaller]
    simp only [List.length_singleton, Nat.pow_one, unsigned, List.foldl_cons,
      List.foldl_nil, Nat.zero_mul, Nat.zero_add ]
    have byte : (UInt8.ofNat (value % 256)).toNat = value % 256 := by
      exact UInt8.toNat_ofNat_of_lt (Nat.mod_lt _ (by decide))
    rw [byte]
    omega

theorem field_encoded_segment (leading suffix : List UInt8) (width value : Nat)
    (fits : value < 256^width) :
    field (leading ++ encodeUnsigned width value ++ suffix) leading.length width = value := by
  simp only [field, List.append_assoc, List.drop_left, List.take_append_of_le_length,
    encodeUnsigned_length, le_refl]
  rw [List.take_of_length_le (by simp)]
  exact encodeUnsigned_decodes width value fits


lemma field_append_before (first second : List UInt8) (offset count : Nat)
    (fits : offset + count ≤ first.length) :
    field (first ++ second) offset count = field first offset count := by
  unfold field
  rw [List.drop_append, List.take_append_of_le_length]
  simp only [List.length_drop]
  omega

lemma field_append_after (first second : List UInt8) (offset count : Nat)
    (fits : first.length ≤ offset) :
    field (first ++ second) offset count = field second (offset - first.length) count := by
  simp [field, List.drop_append, List.drop_eq_nil_of_le fits]

lemma field_encodeUnsigned (width value : Nat) (fits : value < 256^width) :
    field (encodeUnsigned width value) 0 width = value := by
  simpa only [List.nil_append, List.append_nil, List.length_nil] using
    field_encoded_segment [] [] width value fits


lemma field_two_bytes (bytes : List UInt8) (offset : Nat)
    (fits : offset + 2 ≤ bytes.length) :
    field bytes offset 2 = (bytes[offset]?.getD 0).toNat * 256 +
      (bytes[offset + 1]?.getD 0).toNat := by
  have first : bytes[offset]? = (bytes.drop offset)[0]? := by simp
  have second : bytes[offset + 1]? = (bytes.drop offset)[1]? := by simp
  rw [first, second]
  unfold field
  have length : 2 ≤ (bytes.drop offset).length := by simp only [List.length_drop]; omega
  cases shape : bytes.drop offset with
  | nil => simp [shape] at length
  | cons one rest =>
    cases rest with
    | nil => simp [shape] at length
    | cons two rest => simp [unsigned]

lemma decoded_fragment_offset_from_field (packet : PacketPolicy.Packet) (bytes : List UInt8)
    (length : 8 ≤ bytes.length)
    (offset : packet.ipv4FragmentOffset = some (field bytes 6 2 % 8192)) :
    packet.IPv4FragmentOffsetDecoded bytes := by
  refine ⟨length, ?_⟩
  rw [field_two_bytes bytes 6 length] at offset
  exact offset

end TDN.PacketSource
