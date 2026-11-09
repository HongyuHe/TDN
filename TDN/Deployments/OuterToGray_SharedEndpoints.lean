import TDN.Deployments.OuterToGray_SharedData

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma inner_pair_bindings_checked (base : Deployment) :
    ∀ record ∈ records.pairs, record.Bound (records.deployment base) := by exact of_decide_eq_true rfl

lemma inner_address_coverage_checked (base : Deployment) :
    InnerIPsecAddressCoverage (records.deployment base) records.pairs := by exact of_decide_eq_true rfl

lemma local_endpoints_separate (base : Deployment) :
    OuterLocalSeparation (records.deployment base) records.pairs := by exact of_decide_eq_true rfl

lemma inner_endpoints_IPv4 :
    ∀ record ∈ records.pairs, 0 < record.endpoints.sourceAddress ∧
      record.endpoints.sourceAddress < 2^32 ∧ record.endpoints.destinationAddress < 2^32 := by exact of_decide_eq_true rfl

lemma Outer_VPN_options_checked (base : Deployment) :
    ∀ device ∈ (records.deployment base).devices, device.layer = some .outer →
      device.kind = .vpn ∧ (records.deployment base).dropIPv4Options device.id = true := by exact of_decide_eq_true rfl

lemma Outer_gray_mtu_checked (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        InterfaceMtuBound (records.deployment base) interface (interface.mtu.getD 0) := by exact of_decide_eq_true rfl

lemma Outer_gray_ifaces_routed (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        ∀ iface ∈ records.inventory.ifaces, records.inventory.ifaceName iface = interface.id →
          DeriveDataPlaneFromDeviceRecords.RoutedIface records.inventory iface := by exact of_decide_eq_true rfl

end TDN.Deployments.OuterToGray_Shared
