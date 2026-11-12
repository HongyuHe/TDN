import TDN.Import.NativeDecide
import TDN.Deployments.Perimeter_SharedData
import TDN.Requirements.PerimeterDeviceAclChecks

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.Perimeter_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma encryption_rules_checked (base : Deployment) :
    ∀ interface ∈ (deployment base).interfaces,
      ∀ device ∈ (deployment base).devices, interface.device = device.id →
        (CryptographicBoundary device interface →
          BoundaryProtocolChecks (deployment base) records.inventory interface) ∧
        ((device.layer = some .outer ∧ interface.zone = .black) →
          BoundaryPeerChecks (deployment base) records.inventory interface peers) ∧
        ((device.layer = some .inner ∧ interface.zone = .red) →
          BoundaryRedChecks (deployment base) records.inventory interface redEndpoints) := by
  unfold_check_parameters; native_decide

end TDN.Deployments.Perimeter_Shared
