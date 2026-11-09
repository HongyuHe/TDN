import TDN.Deployments.GrayFirewallIptablesChecks
import TDN.Requirements.OuterToGrayDevicePolicyBridge

namespace TDN.Deployments.GrayFirewallCheckedModel
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel GrayFirewallIptablesChecks

lemma registered_model_from_finite_Gray_checks (records : Records)
    (services : List ServiceRegistration) (endpoints : List RedServiceEndpoint)
    (controls : List BoundaryControlFlow) (base : Deployment)
    (address : addressRecordsChecked (registeredDeployment records services endpoints base controls) = true)
    (structureChecked : ProcessingStructuralChecks (records.deployment base) records.inventory)
    (interfaceSelection : ∀ interface ∈ records.interfaces,
      records.ifaceIndex interface ∈ records.inventory.ifaces ∧
      records.inventory.ifaceName (records.ifaceIndex interface) = interface.id)
    (atoms : ∀ iface ∈ records.inventory.ifaces, DeviceProgramAtoms records.inventory iface)
    (ids : InterfaceIDsUnique records.interfaces)
    (core : GrayCoreChecks (registeredDeployment records services endpoints base controls)
      records.inventory records.pairs controls)
    (interfaces : ∀ interface ∈ records.interfaces,
      GrayInterfaceChecks (registeredDeployment records services endpoints base controls)
        records.inventory records.pairs interface)
    (permits : ∀ interface ∈ records.interfaces,
      GrayPermitChecks (registeredDeployment records services endpoints base controls)
        records.inventory records.pairs interface) (required : Bool) :
    msc_gray_firewall_allowlist
      (registeredDeployment records services endpoints base controls) required := by
  let d := registeredDeployment records services endpoints base controls
  obtain ⟨bindings, identifiers, observations, revocation, mechanisms, coverage, unique, ipv4, disjoint⟩ := core
  have workstations := gray_workstation_role_is_empty d observations.2 rfl
  have coherent : d.ProcessingCoherent :=
    records.processing_coherent_from_structure base structureChecked interfaceSelection atoms
  have udp : d.UDPBindingsCoherent := by exact of_decide_eq_true rfl
  have indices := device_policies_have_checked_indices d records.inventory records.ifaceIndex rfl ids
  apply gray_firewall_allowlist_from_native_IPsec_checks d rfl records.inventory rfl
    ⟨fun _ => 64, fun _ => 64⟩ rfl
    (by intro iface; exact ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩)
    records.pairs address workstations coherent udp indices bindings identifiers observations revocation
    rfl rfl mechanisms coverage unique ipv4
  · intro interface member role
    exact (interfaces interface member role).1
  · intro interface member role traffic
    exact declared_control_inventory_has_no_Gray_firewall_approval d controls rfl disjoint interface member role traffic
  · intro interface member role traffic
    change ¬ False
    exact id
  · intro interface member role
    exact (interfaces interface member role).2.1
  · intro interface member role
    exact (interfaces interface member role).2.2.1
  · intro interface member role
    exact (interfaces interface member role).2.2.2.1
  · intro interface member role
    exact (interfaces interface member role).2.2.2.2.2
  · intro interface member role
    exact (interfaces interface member role).2.2.2.2.1
  · intro interface member role direction
    exact permits interface member role direction (by cases direction <;> simp)

end TDN.Deployments.GrayFirewallCheckedModel
