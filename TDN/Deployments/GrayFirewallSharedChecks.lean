import TDN.Import.NativeDecide
import TDN.Deployments.GrayFirewallSharedCheckCommon

namespace TDN.Deployments.GrayFirewallShared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel GrayFirewallIptablesChecks
set_option maxRecDepth 100000
set_option maxHeartbeats 16000000
set_option synthInstance.maxSize 8192

lemma Gray_core_checked (base : Deployment) :
    GrayCoreChecks (deployment base) records.inventory records.pairs controls := by
  exact ⟨Gray_core_pairs_checked base,
    Gray_core_unique_devices_checked base,
    Gray_core_observations_checked base,
    Gray_core_revocation_checked base,
    Gray_core_inner_mechanisms_checked base,
    Gray_core_address_coverage_checked base,
    Gray_core_native_names_checked base,
    Gray_core_address_bounds_checked base,
    Gray_core_control_inventory_checked base⟩

lemma Gray_interfaces_checked (base : Deployment) :
    ∀ interface ∈ records.interfaces,
      GrayInterfaceChecks (deployment base) records.inventory records.pairs interface := by
  unfold_check_parameters; native_decide

lemma Gray_permissions_checked (base : Deployment) :
    ∀ interface ∈ records.interfaces,
      GrayPermitChecks (deployment base) records.inventory records.pairs interface := by
  have checked : ∀ interface ∈ records.interfaces,
      (deployment base).IsDevice interface.device .grayFirewall →
      ∀ direction ∈ [Direction.inbound, .outbound],
        GrayIndexedForwardChecks (deployment base) records.inventory records.pairs selectedRoutes indexedAclPermit
          interface direction := by unfold_check_parameters; native_decide
  intro interface listed role direction member
  exact gray_forward_checks_from_route_certificates _ _ _ _ peer_selected_routes_covered indexedAclPermit _ _
    (indexed_acl_permit_sound base interface listed role direction member)
    (checked interface listed role direction member)

end TDN.Deployments.GrayFirewallShared
