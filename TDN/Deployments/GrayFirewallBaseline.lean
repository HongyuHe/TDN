import TDN.Deployments.GrayFirewallBaselineChecks
import TDN.Deployments.GrayFirewallCheckedModel

namespace TDN.Deployments.Perimeter_Baseline
open Compliance Requirements Requirements.Msc GrayFirewallCheckedModel

theorem complete_native_Gray_firewall_allowlist (base : Deployment) :
    msc_gray_firewall_allowlist (deployment base) true := by
  exact registered_model_from_finite_Gray_checks records services redEndpoints controls base
    (address_inventory_checked base) (device_structure_checked base)
    interface_iface_selection_checked device_program_atoms_checked interface_ids_unique
    (Gray_core_checked base) (Gray_interfaces_checked base) (Gray_permissions_checked base) true

end TDN.Deployments.Perimeter_Baseline
