import TDN.Targets.InterfaceDisablement

namespace TDN.Imported.FreshUnusedInterfaces
open Targets

def interfaces : List UnusedInterfaceState := [⟨"NF_GF_A:gre0", false⟩, ⟨"NF_GF_A:gretap0", false⟩, ⟨"NF_GF_A:erspan0", false⟩, ⟨"NF_I_A1:gre0", false⟩, ⟨"NF_I_A1:gretap0", false⟩, ⟨"NF_I_A1:erspan0", false⟩, ⟨"NF_O_A1:gre0", false⟩, ⟨"NF_O_A1:gretap0", false⟩, ⟨"NF_O_A1:erspan0", false⟩, ⟨"NF_OF_A1:gre0", false⟩, ⟨"NF_OF_A1:gretap0", false⟩, ⟨"NF_OF_A1:erspan0", false⟩, ⟨"NF_I_A2:gre0", false⟩, ⟨"NF_I_A2:gretap0", false⟩, ⟨"NF_I_A2:erspan0", false⟩, ⟨"NF_GF_B:gre0", false⟩, ⟨"NF_GF_B:gretap0", false⟩, ⟨"NF_GF_B:erspan0", false⟩, ⟨"NF_I_B1:gre0", false⟩, ⟨"NF_I_B1:gretap0", false⟩, ⟨"NF_I_B1:erspan0", false⟩, ⟨"NF_O_B1:gre0", false⟩, ⟨"NF_O_B1:gretap0", false⟩, ⟨"NF_O_B1:erspan0", false⟩, ⟨"NF_OF_B1:gre0", false⟩, ⟨"NF_OF_B1:gretap0", false⟩, ⟨"NF_OF_B1:erspan0", false⟩, ⟨"NF_I_B2:gre0", false⟩, ⟨"NF_I_B2:gretap0", false⟩, ⟨"NF_I_B2:erspan0", false⟩, ⟨"NF_I_A3:gre0", false⟩, ⟨"NF_I_A3:gretap0", false⟩, ⟨"NF_I_A3:erspan0", false⟩, ⟨"NF_I_B3:gre0", false⟩, ⟨"NF_I_B3:gretap0", false⟩, ⟨"NF_I_B3:erspan0", false⟩, ⟨"NF_I_A4:gre0", false⟩, ⟨"NF_I_A4:gretap0", false⟩, ⟨"NF_I_A4:erspan0", false⟩, ⟨"NF_I_B4:gre0", false⟩, ⟨"NF_I_B4:gretap0", false⟩, ⟨"NF_I_B4:erspan0", false⟩]

lemma no_active_unused_interface : interfaces.filter (fun interface => interface.enabled) = [] := by decide
lemma actual_unused_inventory_nonempty : interfaces.length = 42 := by decide

theorem captured_unused_interfaces_are_disabled : ∀ interface ∈ interfaces, interface.enabled = false :=
  unused_interfaces_disabled_from_empty_active_subset interfaces no_active_unused_interface

end TDN.Imported.FreshUnusedInterfaces
