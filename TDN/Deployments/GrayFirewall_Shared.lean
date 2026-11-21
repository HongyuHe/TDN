import TDN.Deployments.GrayFirewall_SharedChecks
import TDN.Deployments.GrayFirewall_CheckedModel

namespace TDN.Deployments.GrayFirewall_Shared
open Compliance Requirements Requirements.Msc GrayFirewall_CheckedModel

theorem complete_native_gray_firewall_allowlist (base : Deployment) :
    gray_firewall_allowlist (deployment base) true := by
  exact registered_model_from_finite_gray_checks records services redEndpoints controls base
    (address_inventory_checked base) (device_structure_checked base)
    interface_iface_selection_checked device_program_atoms_checked interface_ids_unique
    (gray_core_checked base) (gray_interfaces_checked base) (gray_permissions_checked base) true

end TDN.Deployments.GrayFirewall_Shared
