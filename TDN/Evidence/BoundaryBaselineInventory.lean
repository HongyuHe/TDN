import TDN.Evidence.BoundaryBaselineData
import TDN.Targets.FiniteInventoryNames
import TDN.Targets.BoundaryNativeChecks

namespace TDN.Imported.BoundaryBaseline
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma address_inventory_checked (base : Deployment) :
    addressRecordsChecked (deployment base) = true := by rfl

lemma no_workstations : ∀ device ∈ records.components, device.kind ≠ .workstation := by
  exact of_decide_eq_true rfl

lemma iface_names_are_nodup : records.ifaceNames.Nodup := by
  exact of_decide_eq_true rfl

lemma interface_ids_unique : InterfaceIDsUnique records.interfaces :=
  interface_ids_unique_from_nodup records.interfaces
    (by change records.ifaceNames.Nodup; exact iface_names_are_nodup)

lemma native_structure_checked (base : Deployment) :
    ProcessingStructuralChecks (records.deployment base) records.inventory := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact indexed_iface_names_unique records.ifaceNames records.nativeIfaces.length rfl iface_names_are_nodup
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl

lemma interface_iface_selection_checked :
    ∀ interface ∈ records.interfaces, records.ifaceIndex interface ∈ records.inventory.ifaces ∧
      records.inventory.ifaceName (records.ifaceIndex interface) = interface.id := by
  exact of_decide_eq_true rfl

lemma native_program_atoms_checked :
    ∀ iface ∈ records.inventory.ifaces, NativeProgramAtoms records.inventory iface := by
  exact of_decide_eq_true rfl

lemma assessed_ifaces_routed :
    ∀ interface ∈ records.interfaces, ∀ device ∈ records.components, interface.device = device.id →
      ((device.layer = some .outer ∧ interface.zone = .black) ∨
        (device.layer = some .inner ∧ interface.zone = .gray) ∨
        (device.layer = some .inner ∧ interface.zone = .red) ∨
        device.kind = .outerFirewall) →
      ∀ iface ∈ records.inventory.ifaces, records.inventory.ifaceName iface = interface.id →
        PolicyDerivation.RoutedIface records.inventory iface := by
  exact of_decide_eq_true rfl

lemma peer_bindings_checked (base : Deployment) :
    ∀ peer ∈ peers, peer.Bound (deployment base) := by
  letI : DecidableRel (deployment base).intendedPeer := fun source destination => by
    change Decidable (∃ tunnel ∈ records.tunnels, tunnel.sender = source ∧ tunnel.receiver = destination)
    infer_instance
  exact of_decide_eq_true rfl

lemma configured_policies_have_recorded_peers :
    ∀ iface ∈ records.inventory.ifaces,
      ∀ policy ∈ records.inventory.configuration.ip.outbound iface,
        ∃ peer ∈ peers,
          peer.source = records.inventory.componentName (records.inventory.configuration.ip.owner iface) ∧
            policy.receiver = peer.destinationAddress := by
  exact of_decide_eq_true rfl

lemma device_roles_checked (base : Deployment) :
    ∀ device ∈ (deployment base).devices,
      (device.layer = some .outer → device.kind = .vpn) ∧
        (device.kind = .outerFirewall → device.layer = none) := by
  exact of_decide_eq_true rfl

end TDN.Imported.BoundaryBaseline
