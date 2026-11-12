import TDN.Import.NativeDecide
import TDN.Deployments.Perimeter_SharedInventory
import TDN.Deployments.Perimeter_SharedRules
import TDN.Deployments.Perimeter_SharedControlChecks
import TDN.Requirements.DevicePerimeterAclProof

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.Perimeter_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel

theorem complete_native_boundary_policy (base : Deployment) :
    msc_boundary_interface_filtering (deployment base) true
      (fun name => firewallInternal.contains name) (localOuter firewalls) := by
  have workstations := gray_workstation_role_is_empty (deployment base) no_workstations rfl
  have address := address_inventory_from_checked_records (deployment base)
    (address_inventory_checked base) workstations
  have coherent : (deployment base).ProcessingCoherent :=
    records.processing_coherent_from_structure base (device_structure_checked base)
      interface_iface_selection_checked device_program_atoms_checked
  have udp : (deployment base).UDPBindingsCoherent := by unfold_check_parameters; native_decide
  have indices := device_policies_have_checked_indices (deployment base) records.inventory
    records.ifaceIndex rfl interface_ids_unique
  apply device_boundary_interface_filtering_from_checks (deployment base) rfl records.inventory rfl
    ⟨fun _ => 64, fun _ => 64⟩ rfl
    (by intro iface; exact ⟨by change 64 ≤ 255; native_decide, by change 64 ≤ 255; native_decide⟩)
    true (fun name => firewallInternal.contains name) (localOuter firewalls) redEndpoints peers controls
    rfl (control_observations_checked base) address coherent udp indices
    (every_declared_Red_endpoint_is_bound records services redEndpoints base controls)
    (peer_bindings_checked base) configured_policies_have_recorded_peers
    (device_roles_checked base)
  · intro interface member device deviceMember owner applicable
    apply assessed_ifaces_routed interface member device deviceMember owner
    rcases applicable with outer | inner | red | ⟨firewall, _⟩
    · exact Or.inl outer
    · exact Or.inr (Or.inl inner)
    · exact Or.inr (Or.inr (Or.inl red))
    · exact Or.inr (Or.inr (Or.inr firewall))
  · intro interface member device deviceMember owner
    obtain ⟨protocol, peer, red⟩ := encryption_rules_checked base interface member device deviceMember owner
    refine ⟨protocol, peer, red, ?_⟩
    intro firewall
    exact firewall_rules_checked base interface member device deviceMember owner firewall.1

end TDN.Deployments.Perimeter_Shared
