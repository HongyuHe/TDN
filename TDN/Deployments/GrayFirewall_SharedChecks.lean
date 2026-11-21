import TDN.Import.CompiledDecide
import TDN.Deployments.GrayFirewall_SharedCheckCommon

namespace TDN.Deployments.GrayFirewall_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel GrayFirewall_IptablesChecks
set_option maxRecDepth 100000
set_option synthInstance.maxSize 8192

lemma gray_core_checked (base : Deployment) :
    GrayCoreChecks (deployment base) records.inventory records.pairs controls := by
  exact ⟨gray_core_pairs_checked base,
    gray_core_unique_devices_checked base,
    gray_core_observations_checked base,
    gray_core_revocation_checked base,
    gray_core_inner_mechanisms_checked base,
    gray_core_address_coverage_checked base,
    gray_core_native_names_checked base,
    gray_core_address_bounds_checked base,
    gray_core_control_inventory_checked base⟩

lemma gray_interfaces_checked (base : Deployment) :
    ∀ interface ∈ records.interfaces,
      GrayInterfaceChecks (deployment base) records.inventory records.pairs interface := by
  unfold_check_parameters; native_decide

lemma gray_permissions_checked (base : Deployment) :
    ∀ interface ∈ records.interfaces,
      GrayPermitChecks (deployment base) records.inventory records.pairs interface := by
  have checked : ∀ interface ∈ records.interfaces,
      (deployment base).IsDevice interface.device .grayFirewall →
      ∀ direction ∈ [Direction.inbound, .outbound],
        GrayIndexedForwardChecks (deployment base) records.inventory records.pairs selectedRoutes indexedAclPermit
          interface direction := by unfold_check_parameters; native_decide
  intro interface listed role direction member
  exact gray_forward_checks_from_indexed_routes _ _ _ _ peer_selected_routes_covered indexedAclPermit _ _
    (indexed_acl_permit_sound base interface listed role direction member)
    (checked interface listed role direction member)

end TDN.Deployments.GrayFirewall_Shared
