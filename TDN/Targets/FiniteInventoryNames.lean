import TDN.Targets.NativePolicies
import Mathlib.Data.List.Nodup

namespace TDN.Targets
open Compliance

theorem interface_ids_unique_from_nodup (interfaces : List Interface)
    (unique : (interfaces.map Interface.id).Nodup) : InterfaceIDsUnique interfaces := by
  have injective := (List.nodup_map_iff_inj_on (unique.of_map Interface.id)).mp unique
  intro first firstMember second secondMember same
  exact injective first firstMember second secondMember same

theorem indexed_iface_names_unique (names : List String) (count : Nat)
    (length : names.length = count) (unique : names.Nodup) :
    ∀ first ∈ List.range count, ∀ second ∈ List.range count,
      names[first]?.getD "unlisted-port" = names[second]?.getD "unlisted-port" → first = second := by
  intro first firstMember second secondMember same
  have firstBound : first < names.length := by simpa [length] using List.mem_range.mp firstMember
  have secondBound : second < names.length := by simpa [length] using List.mem_range.mp secondMember
  have values : names[first] = names[second] := by
    simpa only [List.getElem?_eq_getElem firstBound, List.getElem?_eq_getElem secondBound, Option.getD_some] using same
  exact unique.getElem_inj_iff.mp values

end TDN.Targets
