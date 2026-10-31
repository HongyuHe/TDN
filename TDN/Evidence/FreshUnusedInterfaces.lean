import TDN.Import.Command
import TDN.Targets.InterfaceDisablement

namespace TDN.Imported.FreshUnusedInterfaces
open Targets

tdn_data interfaces : List UnusedInterfaceState from "../../evidence/lean/FreshUnusedInterfaces.json" ["TDN.Imported.FreshUnusedInterfaces.interfaces"]

lemma no_active_unused_interface : interfaces.filter (fun interface => interface.enabled) = [] := by decide
lemma actual_unused_inventory_nonempty : interfaces.length = 42 := by decide

theorem captured_unused_interfaces_are_disabled : ∀ interface ∈ interfaces, interface.enabled = false :=
  unused_interfaces_disabled_from_empty_active_subset interfaces no_active_unused_interface

end TDN.Imported.FreshUnusedInterfaces
