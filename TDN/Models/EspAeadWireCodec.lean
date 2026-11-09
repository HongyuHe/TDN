import TDN.Models.BigEndianByteCodec
import TDN.Models.BlockAlignedEspLength

namespace TDN.ESPWire
open PacketSource

variable {Key : Type}

structure GCMPrimitive (Key : Type) where
  salt : Key → List UInt8
  encrypt : Key → List UInt8 → List UInt8 → List UInt8 → List UInt8
  decrypt : Key → List UInt8 → List UInt8 → List UInt8 → Option (List UInt8)
  encryptedLength : ∀ key nonce aad plaintext,
    (encrypt key nonce aad plaintext).length = plaintext.length + 16
  decryptEncrypted : ∀ key nonce aad plaintext,
    decrypt key nonce aad (encrypt key nonce aad plaintext) = some plaintext


def paddingLength (bytes : Nat) : Nat :=
  (bytes + 2 + 3) / 4 * 4 - (bytes + 2)

lemma padding_length_bound (bytes : Nat) : paddingLength bytes < 4 := by
  unfold paddingLength
  omega

lemma padded_length (bytes : Nat) :
    bytes + paddingLength bytes + 2 = (bytes + 2 + 3) / 4 * 4 := by
  unfold paddingLength
  omega


def padding (bytes : Nat) : List UInt8 :=
  (List.range (paddingLength bytes)).map (fun index => UInt8.ofNat (index + 1))

lemma padding_length (bytes : Nat) : (padding bytes).length = paddingLength bytes := by
  simp [padding]


def protectedPlaintext (plaintext : List UInt8) (nextHeader : Nat) : List UInt8 :=
  plaintext ++ padding plaintext.length ++
    encodeUnsigned 1 (paddingLength plaintext.length) ++ encodeUnsigned 1 nextHeader

lemma protected_plaintext_length (plaintext : List UInt8) (nextHeader : Nat) :
    (protectedPlaintext plaintext nextHeader).length =
      (plaintext.length + 2 + 3) / 4 * 4 := by
  simp only [protectedPlaintext, List.length_append, padding_length, encodeUnsigned_length]
  have total := padded_length plaintext.length
  omega


def espAAD (spi sequence : Nat) : List UInt8 :=
  encodeUnsigned 4 spi ++ encodeUnsigned 4 sequence

lemma aad_length (spi sequence : Nat) : (espAAD spi sequence).length = 8 := by
  simp [espAAD, encodeUnsigned_length]


def encodeESP (primitive : GCMPrimitive Key) (key : Key)
    (spi sequence : Nat) (iv plaintext : List UInt8) (nextHeader : Nat) : List UInt8 :=
  espAAD spi sequence ++ iv ++
    primitive.encrypt key (primitive.salt key ++ iv) (espAAD spi sequence)
      (protectedPlaintext plaintext nextHeader)


def openESP (primitive : GCMPrimitive Key) (key : Key) (wire : List UInt8) :
    Option (List UInt8) :=
  primitive.decrypt key (primitive.salt key ++ (wire.drop 8).take 8) (wire.take 8) (wire.drop 16)

lemma encoded_ESP_length (primitive : GCMPrimitive Key) (key : Key)
    (spi sequence : Nat) (iv plaintext : List UInt8) (nextHeader : Nat)
    (ivLength : iv.length = 8) :
    (encodeESP primitive key spi sequence iv plaintext nextHeader).length =
      PacketLength.alignedWireLength 4 2 32 plaintext.length := by
  simp only [encodeESP, List.length_append, aad_length, ivLength,
    primitive.encryptedLength, protected_plaintext_length, PacketLength.alignedWireLength]
  omega

lemma open_encoded_ESP (primitive : GCMPrimitive Key) (key : Key)
    (spi sequence : Nat) (iv plaintext : List UInt8) (nextHeader : Nat)
    (ivLength : iv.length = 8) :
    openESP primitive key (encodeESP primitive key spi sequence iv plaintext nextHeader) =
      some (protectedPlaintext plaintext nextHeader) := by
  have aadLength := aad_length spi sequence
  let cipher := primitive.encrypt key (primitive.salt key ++ iv) (espAAD spi sequence)
    (protectedPlaintext plaintext nextHeader)
  have aad : (espAAD spi sequence ++ iv ++ cipher).take 8 = espAAD spi sequence := by
    rw [List.append_assoc, ← aadLength]
    simp
  have ivBytes : ((espAAD spi sequence ++ iv ++ cipher).drop 8).take 8 = iv := by
    rw [List.append_assoc, ← aadLength, List.drop_left]
    rw [aadLength, ← ivLength]
    simp
  have cipherBytes : (espAAD spi sequence ++ iv ++ cipher).drop 16 = cipher := by
    have combined : (espAAD spi sequence ++ iv).length = 16 := by
      simp only [List.length_append, aadLength, ivLength]
    rw [← combined, List.drop_left]
  change primitive.decrypt key (primitive.salt key ++ _) _ _ = _
  rw [show encodeESP primitive key spi sequence iv plaintext nextHeader =
    espAAD spi sequence ++ iv ++ cipher from rfl]
  rw [aad, ivBytes, cipherBytes]
  exact primitive.decryptEncrypted key (primitive.salt key ++ iv) (espAAD spi sequence)
    (protectedPlaintext plaintext nextHeader)

def unpadESP (plaintext : List UInt8) : Option (List UInt8 × Nat) :=
  let count := field plaintext (plaintext.length - 2) 1
  let nextHeader := field plaintext (plaintext.length - 1) 1
  if count + 2 ≤ plaintext.length then
    some (plaintext.take (plaintext.length - count - 2), nextHeader)
  else none

lemma unpad_protected_plaintext (plaintext : List UInt8) (nextHeader : Nat)
    (nextFits : nextHeader < 256) :
    unpadESP (protectedPlaintext plaintext nextHeader) = some (plaintext, nextHeader) := by
  have padFits : paddingLength plaintext.length < 256 :=
    (padding_length_bound plaintext.length).trans (by decide)
  have countField : field (protectedPlaintext plaintext nextHeader)
      ((protectedPlaintext plaintext nextHeader).length - 2) 1 = paddingLength plaintext.length := by
    have location : (protectedPlaintext plaintext nextHeader).length - 2 =
        (plaintext ++ padding plaintext.length).length := by
      simp only [protectedPlaintext, List.length_append, encodeUnsigned_length]
      omega
    rw [location]
    exact field_encoded_segment (plaintext ++ padding plaintext.length)
      (encodeUnsigned 1 nextHeader) 1 (paddingLength plaintext.length) padFits
  have nextField : field (protectedPlaintext plaintext nextHeader)
      ((protectedPlaintext plaintext nextHeader).length - 1) 1 = nextHeader := by
    have location : (protectedPlaintext plaintext nextHeader).length - 1 =
        (plaintext ++ padding plaintext.length ++ encodeUnsigned 1 (paddingLength plaintext.length)).length := by
      simp only [protectedPlaintext, List.length_append, encodeUnsigned_length]
      omega
    rw [location]
    simpa only [List.append_nil, protectedPlaintext] using field_encoded_segment
      (plaintext ++ padding plaintext.length ++ encodeUnsigned 1 (paddingLength plaintext.length))
      [] 1 nextHeader nextFits
  have length : (protectedPlaintext plaintext nextHeader).length =
      plaintext.length + paddingLength plaintext.length + 2 := by
    simp only [protectedPlaintext, List.length_append, encodeUnsigned_length, padding_length]
  unfold unpadESP
  rw [countField, nextField]
  simp only [length]
  have fits : paddingLength plaintext.length + 2 ≤
      plaintext.length + paddingLength plaintext.length + 2 := by omega
  rw [if_pos fits]
  have offset : plaintext.length + paddingLength plaintext.length + 2 -
      paddingLength plaintext.length - 2 = plaintext.length := by omega
  rw [offset]
  congr 1
  simp [protectedPlaintext, List.append_assoc]

def decodeESP (primitive : GCMPrimitive Key) (key : Key) (wire : List UInt8) :
    Option (List UInt8 × Nat) :=
  (openESP primitive key wire).bind unpadESP

theorem decode_encoded_ESP (primitive : GCMPrimitive Key) (key : Key)
    (spi sequence : Nat) (iv plaintext : List UInt8) (nextHeader : Nat)
    (ivLength : iv.length = 8) (nextFits : nextHeader < 256) :
    decodeESP primitive key (encodeESP primitive key spi sequence iv plaintext nextHeader) =
      some (plaintext, nextHeader) := by
  rw [decodeESP, open_encoded_ESP primitive key spi sequence iv plaintext nextHeader ivLength]
  exact unpad_protected_plaintext plaintext nextHeader nextFits


end TDN.ESPWire
