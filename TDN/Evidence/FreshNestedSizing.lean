import TDN.Targets.NestedPacketSizing

namespace TDN.Imported.FreshNestedSizing
open TDN.Targets.NestedSizing

def espLength := PacketLength.alignedWireLength 4 2 52

def interfaces : List InterfaceLimit := [
  ⟨"FA", "inside", .black, 1500⟩,
  ⟨"FA", "outside", .black, 1500⟩,
  ⟨"FB", "inside", .black, 1500⟩,
  ⟨"FB", "outside", .black, 1500⟩,
  ⟨"HA", "red", .red, 1100⟩,
  ⟨"HB", "red", .red, 1100⟩,
  ⟨"IA", "red", .red, 1100⟩,
  ⟨"IA", "gray", .gray, 1200⟩,
  ⟨"IB", "red", .red, 1100⟩,
  ⟨"IB", "gray", .gray, 1200⟩,
  ⟨"OA", "gray", .gray, 1500⟩,
  ⟨"OA", "black", .black, 1400⟩,
  ⟨"OB", "gray", .gray, 1500⟩,
  ⟨"OB", "black", .black, 1400⟩]

def redLimit : Nat := 1100

lemma every_maximum_fits : ∀ entry ∈ interfaces,
    lengthAt espLength espLength entry.stage redLimit ≤ entry.mtu := by decide

/-- The identical proof applies to every imported interface and every smaller
Red IP datagram under the fixed two-layer encoding contract. -/
theorem every_bounded_red_datagram_fits_each_stage :
    ∀ bytes, bytes ≤ redLimit → ∀ entry ∈ interfaces,
      lengthAt espLength espLength entry.stage bytes ≤ entry.mtu :=
  all_sizes_fit_each_interface espLength espLength
    (PacketLength.aligned_wire_length_monotone 4 2 52)
    (PacketLength.aligned_wire_length_monotone 4 2 52)
    interfaces redLimit every_maximum_fits

end TDN.Imported.FreshNestedSizing
