import TDN.Semantics.BinaryWire

namespace TDN.PacketSource

def encodeVLANs : List Nat → List UInt8
  | [] => []
  | tag :: rest => encodeUnsigned 2 33024 ++ encodeUnsigned 2 tag ++ encodeVLANs rest

@[simp] lemma encoded_VLAN_length (tags : List Nat) :
    (encodeVLANs tags).length = 4 * tags.length := by
  induction tags with
  | nil => rfl
  | cons tag rest ih => simp [encodeVLANs, ih]; omega

lemma encoded_VLAN_fields (tags : List Nat) (suffix : List UInt8)
    (bounds : ∀ tag ∈ tags, tag < 65536) (index : Nat) (member : index < tags.length) :
    field (encodeVLANs tags ++ suffix) (index * 4) 2 = 33024 ∧
    tags[index]? = some (field (encodeVLANs tags ++ suffix) (2 + index * 4) 2) := by
  induction tags generalizing index with
  | nil => simp at member
  | cons tag rest ih =>
    have tagBound := bounds tag (List.mem_cons_self ..)
    cases index with
    | zero =>
      simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only
        [encodeVLANs, List.append_assoc, Nat.zero_mul, Nat.zero_add, Nat.reduceAdd,
          field_append_before, field_append_after, encodeUnsigned_length,
          field_encodeUnsigned, Nat.reduceSub, Nat.reducePow, List.getElem?_cons_zero, and_self]
    | succ index =>
      have tailBounds : ∀ value ∈ rest, value < 65536 :=
        fun value inTail => bounds value (List.mem_cons_of_mem _ inTail)
      have inTail : index < rest.length := by simpa using member
      have previous := ih tailBounds index inTail
      simp (disch := (simp only [encodeUnsigned_length, List.length_append, Nat.reducePow]; omega)) only
        [encodeVLANs, List.append_assoc, field_append_after, encodeUnsigned_length,
          List.getElem?_cons_succ]
      have firstOffset : (index + 1) * 4 - 2 - 2 = index * 4 := by omega
      have secondOffset : 2 + (index + 1) * 4 - 2 - 2 = 2 + index * 4 := by omega
      rw [firstOffset, secondOffset]
      exact previous

def encodeEthernetHeader (header : LayeredFrame.EthernetHeader) : List UInt8 :=
  encodeUnsigned 6 header.destination ++ encodeUnsigned 6 header.source ++
  encodeVLANs header.vlanTags ++ encodeUnsigned 2 header.etherType

@[simp] lemma encoded_Ethernet_header_length (header : LayeredFrame.EthernetHeader) :
    (encodeEthernetHeader header).length = 14 + 4 * header.vlanTags.length := by
  simp [encodeEthernetHeader]
  omega

theorem encoded_Ethernet_header_matches (header : LayeredFrame.EthernetHeader)
    (source : header.source < 2^48) (destination : header.destination < 2^48)
    (etherType : header.etherType < 65536)
    (tags : ∀ tag ∈ header.vlanTags, tag < 65536) :
    EthernetHeaderMatches header (encodeEthernetHeader header) := by
  refine ⟨encoded_Ethernet_header_length header, ?_, ?_, ?_, ?_⟩
  · simp (disch := (simp only [encodeUnsigned_length, encoded_VLAN_length,
      List.length_append, Nat.reducePow]; omega)) only [encodeEthernetHeader, List.append_assoc,
      field_append_before, field_append_after, encodeUnsigned_length, field_encodeUnsigned]
  · simp (disch := (simp only [encodeUnsigned_length, encoded_VLAN_length,
      List.length_append, Nat.reducePow]; omega)) only [encodeEthernetHeader, List.append_assoc,
      field_append_before, field_append_after, encodeUnsigned_length, field_encodeUnsigned, Nat.reduceSub]
  · intro index member
    have fields := encoded_VLAN_fields header.vlanTags (encodeUnsigned 2 header.etherType) tags index member
    simp (disch := (simp only [encodeUnsigned_length, encoded_VLAN_length,
      List.length_append, Nat.reducePow]; omega)) only [encodeEthernetHeader, List.append_assoc,
      field_append_after, encodeUnsigned_length]
    have firstOffset : 12 + index * 4 - 6 - 6 = index * 4 := by omega
    have secondOffset : 14 + index * 4 - 6 - 6 = 2 + index * 4 := by omega
    rw [firstOffset, secondOffset]
    exact fields
  · simp (disch := (simp only [encodeUnsigned_length, encoded_VLAN_length,
      List.length_append, Nat.reducePow]; omega)) only [encodeEthernetHeader, List.append_assoc,
      field_append_after, encodeUnsigned_length, encoded_VLAN_length]
    have offset : 12 + 4 * header.vlanTags.length - 6 - 6 - 4 * header.vlanTags.length = 0 := by omega
    rw [offset]
    exact field_encodeUnsigned 2 header.etherType etherType

end TDN.PacketSource
