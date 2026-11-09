import TDN.Deployments.GrayFirewallSharedRuleShard006
import TDN.Deployments.GrayFirewallSharedRuleShard007
import TDN.Deployments.GrayFirewallSharedRuleShard008
import TDN.Deployments.GrayFirewallSharedRuleShard009
import TDN.Deployments.GrayFirewallSharedRuleShard010
import TDN.Deployments.GrayFirewallSharedRuleShard011
import TDN.Deployments.GrayFirewallSharedRuleShard012
import TDN.Deployments.GrayFirewallSharedRuleShard013
import TDN.Deployments.GrayFirewallSharedRuleShard014
import TDN.Deployments.GrayFirewallSharedRuleShard015
import TDN.Deployments.GrayFirewallSharedRuleShard016
import TDN.Deployments.GrayFirewallSharedRuleShard017
import TDN.Deployments.GrayFirewallSharedRuleShard018
import TDN.Deployments.GrayFirewallSharedRuleShard019
import TDN.Deployments.GrayFirewallSharedRuleShard020
import TDN.Deployments.GrayFirewallSharedRuleShard021
import TDN.Deployments.GrayFirewallSharedRuleShard022
import TDN.Deployments.GrayFirewallSharedRuleShard023
import TDN.Deployments.GrayFirewallSharedRuleShard024
import TDN.Deployments.GrayFirewallSharedRuleShard025
import TDN.Deployments.GrayFirewallSharedRuleShard026
import TDN.Deployments.GrayFirewallSharedRuleShard027
import TDN.Deployments.GrayFirewallSharedRuleShard028
import TDN.Deployments.GrayFirewallSharedRuleShard029

namespace TDN.Deployments.GrayFirewallShared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel GrayFirewallIptablesChecks
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
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
  refine (List.forall_mem_iff_forall_getElem
    (P := fun interface => GrayInterfaceChecks (deployment base) records.inventory records.pairs interface)
    (l := records.interfaces)).mpr ?_
  intro index bound
  by_cases selected : index ∈ Gray_checked_indices
  · simp only [Gray_checked_indices, List.mem_cons, List.not_mem_nil, or_false] at selected
    rcases selected with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · exact Gray_interface_006_checked base
    · exact Gray_interface_007_checked base
    · exact Gray_interface_008_checked base
    · exact Gray_interface_009_checked base
    · exact Gray_interface_010_checked base
    · exact Gray_interface_011_checked base
    · exact Gray_interface_012_checked base
    · exact Gray_interface_013_checked base
    · exact Gray_interface_014_checked base
    · exact Gray_interface_015_checked base
    · exact Gray_interface_016_checked base
    · exact Gray_interface_017_checked base
    · exact Gray_interface_018_checked base
    · exact Gray_interface_019_checked base
    · exact Gray_interface_020_checked base
    · exact Gray_interface_021_checked base
    · exact Gray_interface_022_checked base
    · exact Gray_interface_023_checked base
    · exact Gray_interface_024_checked base
    · exact Gray_interface_025_checked base
    · exact Gray_interface_026_checked base
    · exact Gray_interface_027_checked base
    · exact Gray_interface_028_checked base
    · exact Gray_interface_029_checked base
  · intro role
    exact False.elim (Gray_unselected_not_firewall base ⟨index, bound⟩ selected role)

lemma Gray_permissions_checked (base : Deployment) :
    ∀ interface ∈ records.interfaces,
      GrayPermitChecks (deployment base) records.inventory records.pairs interface := by
  refine (List.forall_mem_iff_forall_getElem
    (P := fun interface => GrayPermitChecks (deployment base) records.inventory records.pairs interface)
    (l := records.interfaces)).mpr ?_
  intro index bound
  by_cases selected : index ∈ Gray_checked_indices
  · simp only [Gray_checked_indices, List.mem_cons, List.not_mem_nil, or_false] at selected
    rcases selected with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · exact Gray_permission_006_checked base
    · exact Gray_permission_007_checked base
    · exact Gray_permission_008_checked base
    · exact Gray_permission_009_checked base
    · exact Gray_permission_010_checked base
    · exact Gray_permission_011_checked base
    · exact Gray_permission_012_checked base
    · exact Gray_permission_013_checked base
    · exact Gray_permission_014_checked base
    · exact Gray_permission_015_checked base
    · exact Gray_permission_016_checked base
    · exact Gray_permission_017_checked base
    · exact Gray_permission_018_checked base
    · exact Gray_permission_019_checked base
    · exact Gray_permission_020_checked base
    · exact Gray_permission_021_checked base
    · exact Gray_permission_022_checked base
    · exact Gray_permission_023_checked base
    · exact Gray_permission_024_checked base
    · exact Gray_permission_025_checked base
    · exact Gray_permission_026_checked base
    · exact Gray_permission_027_checked base
    · exact Gray_permission_028_checked base
    · exact Gray_permission_029_checked base
  · intro role
    exact False.elim (Gray_unselected_not_firewall base ⟨index, bound⟩ selected role)


end TDN.Deployments.GrayFirewallShared
