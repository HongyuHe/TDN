import TDN.Import.NativeDecide
import TDN.Deployments.Perimeter_BaselineData
import TDN.Requirements.PerimeterDeviceAclChecks

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.Perimeter_Baseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma control_observations_checked (base : Deployment) :
    BoundaryControlObservationChecks (deployment base) controls := by
  unfold_check_parameters; native_decide

lemma firewall_rules_checked (base : Deployment) :
    ∀ interface ∈ (deployment base).interfaces,
      ∀ device ∈ (deployment base).devices, interface.device = device.id →
        device.kind = .outerFirewall →
          (deployment base).IsLayer (localOuter firewalls device.id) .outer ∧
            BoundaryFirewallChecks (deployment base) records.inventory controls interface
              (localOuter firewalls device.id) (firewallInternal.contains interface.id) := by
  unfold_check_parameters; native_decide

end TDN.Deployments.Perimeter_Baseline
