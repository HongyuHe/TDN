import TDN.Deployments.DeviceCheckDefaults
import TDN.Import.CompiledDecide
import TDN.Deployments.OuterToGray_SharedGrayInterfaces

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000

lemma gray2_inbound_lookup (base : Deployment) :
    records.RouteFirstMaskLookup base (outerGrayInterfaces[2]'(by native_decide)) .inbound := by
  close_check_with emptyDeploymentForChecks; native_decide

lemma gray2_outbound_lookup (base : Deployment) :
    records.RouteFirstMaskLookup base (outerGrayInterfaces[2]'(by native_decide)) .outbound := by
  close_check_with emptyDeploymentForChecks; native_decide

end TDN.Deployments.OuterToGray_Shared
