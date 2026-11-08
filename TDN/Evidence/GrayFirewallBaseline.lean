import TDN.Evidence.GrayFirewallBaselineChecks
import TDN.Evidence.GrayFirewallCheckedModel

namespace TDN.Imported.BoundaryBaseline
open Compliance Targets Targets.Complete GrayFirewallCheckedModel

theorem complete_native_Gray_firewall_allowlist (base : Deployment) :
    msc_gray_firewall_allowlist (deployment base) true := by
  exact registered_model_from_finite_Gray_checks records services redEndpoints controls base
    (address_inventory_checked base) (native_structure_checked base)
    interface_iface_selection_checked native_program_atoms_checked interface_ids_unique
    (Gray_core_checked base) (Gray_interfaces_checked base) (Gray_permissions_checked base) true

end TDN.Imported.BoundaryBaseline
