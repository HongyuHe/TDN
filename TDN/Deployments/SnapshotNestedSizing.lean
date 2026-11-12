import TDN.Import.SnapshotLoader
import TDN.Requirements.DoubleEncapMtuCalculation

namespace TDN.Deployments.SnapshotNestedSizing
open TDN.Requirements.NestedSizing

def espLength := PacketLength.alignedWireLength 4 2 52

load_network_records interfaces : List InterfaceLimit from "../../data/evidence/SnapshotNestedSizing.json" ["TDN.Deployments.SnapshotNestedSizing.interfaces"]

load_network_records redLimit : Nat from "../../data/evidence/SnapshotNestedSizing.json" ["TDN.Deployments.SnapshotNestedSizing.redLimit"]

lemma every_maximum_fits : ∀ entry ∈ interfaces,
    lengthAt espLength espLength entry.stage redLimit ≤ entry.mtu := by native_decide

theorem every_bounded_red_datagram_fits_each_stage :
    ∀ bytes, bytes ≤ redLimit → ∀ entry ∈ interfaces,
      lengthAt espLength espLength entry.stage bytes ≤ entry.mtu :=
  all_sizes_fit_each_interface espLength espLength
    (PacketLength.aligned_wire_length_monotone 4 2 52)
    (PacketLength.aligned_wire_length_monotone 4 2 52)
    interfaces redLimit every_maximum_fits

end TDN.Deployments.SnapshotNestedSizing
