import TDN.Import.Command
import TDN.Targets.NestedPacketSizing

namespace TDN.Imported.FreshNestedSizing
open TDN.Targets.NestedSizing

def espLength := PacketLength.alignedWireLength 4 2 52

tdn_data interfaces : List InterfaceLimit from "../../data/evidence/FreshNestedSizing.json" ["TDN.Imported.FreshNestedSizing.interfaces"]

tdn_data redLimit : Nat from "../../data/evidence/FreshNestedSizing.json" ["TDN.Imported.FreshNestedSizing.redLimit"]

lemma every_maximum_fits : ∀ entry ∈ interfaces,
    lengthAt espLength espLength entry.stage redLimit ≤ entry.mtu := by decide

theorem every_bounded_red_datagram_fits_each_stage :
    ∀ bytes, bytes ≤ redLimit → ∀ entry ∈ interfaces,
      lengthAt espLength espLength entry.stage bytes ≤ entry.mtu :=
  all_sizes_fit_each_interface espLength espLength
    (PacketLength.aligned_wire_length_monotone 4 2 52)
    (PacketLength.aligned_wire_length_monotone 4 2 52)
    interfaces redLimit every_maximum_fits

end TDN.Imported.FreshNestedSizing
