import TDN.Import.CompiledDecide
import TDN.Deployments.GrayFirewall_SharedInventory
import TDN.Deployments.GrayFirewall_SharedRouteHints
import TDN.Deployments.GrayFirewall_SharedAclHints
import TDN.Requirements.GrayFirewallIndexedForwardChecks
import TDN.Deployments.GrayFirewall_IptablesChecks

namespace TDN.Deployments.GrayFirewall_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel GrayFirewall_IptablesChecks
set_option maxRecDepth 100000
set_option synthInstance.maxSize 8192

instance instDecidableSharedGrayPeer (base : Deployment) : DecidableRel (deployment base).intendedPeer := by
  change DecidableRel (fun source destination => ∃ tunnel ∈ records.tunnels,
    tunnel.sender = source ∧ tunnel.receiver = destination)
  infer_instance

instance instDecidableSharedGraySource (base : Deployment) (name : String) :
    DecidablePred ((deployment base).reachableSource name) := by
  intro address
  change Decidable (records.reachableSource name address)
  match found : routeHintFor address with
  | none => infer_instance
  | some hint =>
    exact decidable_of_iff (reachableSourceFromSelected name address)
      (reachable_source_from_selected_iff name address hint found)

lemma gray_core_pairs_checked (base : Deployment) :
    ∀ record ∈ records.pairs, record.Bound (deployment base) := by
  unfold_check_parameters; native_decide

lemma gray_core_unique_devices_checked (base : Deployment) :
    ∀ first ∈ (deployment base).devices, ∀ second ∈ (deployment base).devices, first.id = second.id → first = second := by
  unfold_check_parameters; native_decide

lemma gray_core_observations_checked (base : Deployment) :
    GrayIPsecObservationChecks (deployment base) := by
  unfold_check_parameters; native_decide

lemma gray_core_revocation_checked (base : Deployment) :
    GrayRevocationServiceAbsent (deployment base) := by
  unfold_check_parameters; native_decide

lemma gray_core_inner_mechanisms_checked (base : Deployment) :
    ∀ tunnel ∈ (deployment base).tunnels, tunnel.layer = .inner → tunnel.protocol = .ipsec := by
  unfold_check_parameters; native_decide

lemma gray_core_address_coverage_checked (base : Deployment) :
    InnerIPsecAddressCoverage (deployment base) records.pairs := by
  unfold_check_parameters; native_decide

lemma gray_core_native_names_checked (base : Deployment) :
    DeviceNamesUniqueByComponent records.inventory := by
  native_decide

lemma gray_core_address_bounds_checked (base : Deployment) :
    ∀ record ∈ records.pairs, 0 < record.endpoints.sourceAddress ∧ record.endpoints.sourceAddress < 2^32 ∧ record.endpoints.destinationAddress < 2^32 := by
  native_decide

lemma gray_core_control_inventory_checked (base : Deployment) :
    GrayControlInventoryDisjoint (deployment base) controls := by
  unfold_check_parameters; native_decide

end TDN.Deployments.GrayFirewall_Shared
