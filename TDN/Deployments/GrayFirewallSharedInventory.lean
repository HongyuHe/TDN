import TDN.Import.NativeDecide
import TDN.Deployments.GrayFirewallSharedData
import TDN.Deployments.GrayFirewallSharedAddresses
import TDN.Deployments.GrayFirewallSharedStructure
import TDN.Requirements.PerimeterDeviceAclChecks

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.GrayFirewallShared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma interface_iface_selection_checked :
    ∀ interface ∈ records.interfaces, records.ifaceIndex interface ∈ records.inventory.ifaces ∧
      records.inventory.ifaceName (records.ifaceIndex interface) = interface.id := by
  native_decide

lemma device_program_atoms_checked :
    ∀ iface ∈ records.inventory.ifaces, DeviceProgramAtoms records.inventory iface := by
  native_decide

lemma assessed_ifaces_routed :
    ∀ interface ∈ records.interfaces, ∀ device ∈ records.components, interface.device = device.id →
      ((device.layer = some .outer ∧ interface.zone = .black) ∨
        (device.layer = some .inner ∧ interface.zone = .gray) ∨
        (device.layer = some .inner ∧ interface.zone = .red) ∨
        device.kind = .outerFirewall) →
      ∀ iface ∈ records.inventory.ifaces, records.inventory.ifaceName iface = interface.id →
        DeriveDataPlaneFromDeviceRecords.RoutedIface records.inventory iface := by
  native_decide

lemma peer_bindings_checked (base : Deployment) :
    ∀ peer ∈ peers, peer.Bound (deployment base) := by
  letI : DecidableRel (deployment base).intendedPeer := fun source destination => by
    change Decidable (∃ tunnel ∈ records.tunnels, tunnel.sender = source ∧ tunnel.receiver = destination)
    infer_instance
  unfold_check_parameters; native_decide

lemma configured_policies_have_recorded_peers :
    ∀ iface ∈ records.inventory.ifaces,
      ∀ policy ∈ records.inventory.configuration.ip.egressPolicies iface,
        ∃ peer ∈ peers,
          peer.source = records.inventory.componentName (records.inventory.configuration.ip.owner iface) ∧
            policy.receiver = peer.destinationAddress := by
  native_decide

lemma device_roles_checked (base : Deployment) :
    ∀ device ∈ (deployment base).devices,
      (device.layer = some .outer → device.kind = .vpn) ∧
        (device.kind = .outerFirewall → device.layer = none) := by
  unfold_check_parameters; native_decide

end TDN.Deployments.GrayFirewallShared
