import TDN.Deployments.NativeCheckDefaults
import TDN.Import.NativeDecide
import TDN.Deployments.OuterToGray_BaselineData

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.OuterToGray_Baseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma every_packet_mask_has_an_ordered_allowance :
    ∀ entry ∈ records.masks,
      entry.packet.IsPermittedByAclChain (DataPlaneForwarding.deviceAt records.nativeDevices entry.owner).forwardRules := by native_decide

lemma pair_and_mask_inventories_nonempty : records.pairs ≠ [] ∧ records.masks ≠ [] := by native_decide

end TDN.Deployments.OuterToGray_Baseline

namespace TDN.Deployments.OuterToGray_Baseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma address_inventory_checked (base : Deployment) :
    addressRecordsChecked (records.deployment base) = true := by rfl

lemma interface_ids_unique : InterfaceIDsUnique records.interfaces := by native_decide

lemma device_structure_checked (base : Deployment) :
    ProcessingStructuralChecks (records.deployment base) records.inventory := by unfold_check_parameters; native_decide

lemma interface_iface_selection_checked :
    ∀ interface ∈ records.interfaces, records.ifaceIndex interface ∈ records.inventory.ifaces ∧
      records.inventory.ifaceName (records.ifaceIndex interface) = interface.id := by native_decide

lemma device_program_atoms_checked :
    ∀ iface ∈ records.inventory.ifaces, DeviceProgramAtoms records.inventory iface := by native_decide

lemma inner_pair_bindings_checked (base : Deployment) :
    ∀ record ∈ records.pairs, record.Bound (records.deployment base) := by unfold_check_parameters; native_decide

lemma inner_address_coverage_checked (base : Deployment) :
    InnerIPsecAddressCoverage (records.deployment base) records.pairs := by unfold_check_parameters; native_decide

lemma local_endpoints_separate (base : Deployment) :
    OuterLocalSeparation (records.deployment base) records.pairs := by unfold_check_parameters; native_decide

lemma inner_endpoints_IPv4 :
    ∀ record ∈ records.pairs, 0 < record.endpoints.sourceAddress ∧
      record.endpoints.sourceAddress < 2^32 ∧ record.endpoints.destinationAddress < 2^32 := by native_decide

lemma Outer_VPN_options_checked (base : Deployment) :
    ∀ device ∈ (records.deployment base).devices, device.layer = some .outer →
      device.kind = .vpn ∧ (records.deployment base).dropIPv4Options device.id = true := by unfold_check_parameters; native_decide

lemma Outer_gray_mtu_checked (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        InterfaceMtuBound (records.deployment base) interface (interface.mtu.getD 0) := by unfold_check_parameters; native_decide

lemma Outer_gray_ifaces_routed (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        ∀ iface ∈ records.inventory.ifaces, records.inventory.ifaceName iface = interface.id →
          DeriveDataPlaneFromDeviceRecords.RoutedIface records.inventory iface := by unfold_check_parameters; native_decide

lemma Outer_gray_allow_rules_checked (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        ∀ iface ∈ records.inventory.ifaces, records.inventory.ifaceName iface = interface.id →
          ∀ policy ∈ (records.deployment base).policies, policy.interface = interface.id →
            policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
              OuterGrayRuleChecks (records.deployment base) interface
                (records.inventory.configuration.ip.interfaceName iface) policy.direction records.pairs rule := by
  unfold_check_parameters; native_decide

lemma Outer_gray_forward_masks_checked (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        ∀ direction ∈ [Direction.inbound, .outbound],
          records.ForwardMaskLookup base interface direction := by
  close_check_with emptyDeploymentForChecks; native_decide

lemma Outer_gray_forward_coverage_checked (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        ∀ direction ∈ [Direction.inbound, .outbound],
          OuterGrayForwardChecks (records.deployment base) records.inventory records.pairs interface direction := by
  intro interface member outer gray direction allowedDirection
  exact records.forward_checks_from_mask_lookup base interface_ids_unique
    every_packet_mask_has_an_ordered_allowance interface member direction
    (Outer_gray_forward_masks_checked base interface member outer gray direction allowedDirection)

lemma no_workstations : ∀ device ∈ records.components, device.kind ≠ .workstation := by
  native_decide

lemma all_inner_tunnels_IPsec :
    ∀ tunnel ∈ records.tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec := by
  native_decide

end TDN.Deployments.OuterToGray_Baseline
