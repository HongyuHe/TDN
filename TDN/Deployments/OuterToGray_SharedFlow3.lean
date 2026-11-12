import TDN.Deployments.NativeCheckDefaults
import TDN.Import.NativeDecide
import TDN.Deployments.OuterToGray_SharedGrayInterfaces

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma gray3_inbound_lookup (base : Deployment) :
    records.RouteFirstMaskLookup base (outerGrayInterfaces[3]'(by native_decide)) .inbound := by
  close_check_with emptyDeploymentForChecks; native_decide

lemma gray3_outbound_lookup (base : Deployment) :
    records.RouteFirstMaskLookup base (outerGrayInterfaces[3]'(by native_decide)) .outbound := by
  close_check_with emptyDeploymentForChecks; native_decide

end TDN.Deployments.OuterToGray_Shared
