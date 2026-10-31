import TDN.Import.Command
import TDN.Targets.Operations

namespace TDN.Imported.NativeInventory

set_option maxRecDepth 100000

tdn_data resolverConfigurations : List (String × List Targets.DNSAddress) from "../../evidence/lean/NativeInventory.json" ["TDN.Imported.NativeInventory.resolverConfigurations"]

theorem every_recorded_component_has_specified_dns_server : resolverConfigurations ≠ [] ∧ ∀ c ∈ resolverConfigurations, c.2 ≠ [] := by unfold resolverConfigurations; decide

tdn_data rootAccess : List (String × Bool × Bool) from "../../evidence/lean/NativeInventory.json" ["TDN.Imported.NativeInventory.rootAccess"]

theorem recorded_root_passwords_locked : rootAccess ≠ [] ∧ ∀ r ∈ rootAccess, r.2.1 = true ∧ r.2.2 = false := by unfold rootAccess; decide

tdn_data routingNames : List String from "../../evidence/lean/NativeInventory.json" ["TDN.Imported.NativeInventory.routingNames"]

tdn_data encryptorProcesses : List (String × List String) from "../../evidence/lean/NativeInventory.json" ["TDN.Imported.NativeInventory.encryptorProcesses"]

theorem no_recorded_encryptor_process_has_known_routing_name : encryptorProcesses ≠ [] ∧ ∀ c ∈ encryptorProcesses, ∀ name ∈ c.2, name ∉ routingNames := by unfold encryptorProcesses routingNames; decide

end TDN.Imported.NativeInventory
