import TDN.Deployments.GrayFirewallSharedInventory
import TDN.Deployments.GrayFirewallSharedRouteCertificates
import TDN.Deployments.GrayFirewallSharedAclCertificates
import TDN.Requirements.GrayFirewallIndexedForwardChecks
import TDN.Deployments.GrayFirewallIptablesChecks

namespace TDN.Deployments.GrayFirewallShared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel GrayFirewallIptablesChecks
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000
set_option synthInstance.maxSize 8192

instance instDecidableSharedGrayPeer (base : Deployment) : DecidableRel (deployment base).intendedPeer := by
  change DecidableRel (fun source destination => ∃ tunnel ∈ records.tunnels,
    tunnel.sender = source ∧ tunnel.receiver = destination)
  infer_instance

instance instDecidableSharedGraySource (base : Deployment) (name : String) :
    DecidablePred ((deployment base).reachableSource name) := by
  intro address
  change Decidable (records.reachableSource name address)
  match found : certificateFor address with
  | none => infer_instance
  | some certificate =>
    exact decidable_of_iff (reachableSourceFromSelected name address)
      (reachable_source_from_selected_iff name address certificate found)

lemma Gray_core_pairs_checked (base : Deployment) :
    ∀ record ∈ records.pairs, record.Bound (deployment base) := by
  exact of_decide_eq_true rfl

lemma Gray_core_unique_devices_checked (base : Deployment) :
    ∀ first ∈ (deployment base).devices, ∀ second ∈ (deployment base).devices, first.id = second.id → first = second := by
  exact of_decide_eq_true rfl

lemma Gray_core_observations_checked (base : Deployment) :
    GrayIPsecObservationChecks (deployment base) := by
  exact of_decide_eq_true rfl

lemma Gray_core_revocation_checked (base : Deployment) :
    GrayRevocationServiceAbsent (deployment base) := by
  exact of_decide_eq_true rfl

lemma Gray_core_inner_mechanisms_checked (base : Deployment) :
    ∀ tunnel ∈ (deployment base).tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec := by
  exact of_decide_eq_true rfl

lemma Gray_core_address_coverage_checked (base : Deployment) :
    InnerIPsecAddressCoverage (deployment base) records.pairs := by
  exact of_decide_eq_true rfl

lemma Gray_core_native_names_checked (base : Deployment) :
    DeviceNamesUniqueByComponent records.inventory := by
  exact of_decide_eq_true rfl

lemma Gray_core_address_bounds_checked (base : Deployment) :
    ∀ record ∈ records.pairs, 0 < record.endpoints.sourceAddress ∧ record.endpoints.sourceAddress < 2^32 ∧ record.endpoints.destinationAddress < 2^32 := by
  exact of_decide_eq_true rfl

lemma Gray_core_control_inventory_checked (base : Deployment) :
    GrayControlInventoryDisjoint (deployment base) controls := by
  exact of_decide_eq_true rfl

end TDN.Deployments.GrayFirewallShared
