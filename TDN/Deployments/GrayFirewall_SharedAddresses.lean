import TDN.Deployments.GrayFirewall_SharedData
import TDN.Requirements.DeviceAndInterfaceNameTable
import TDN.Requirements.PerimeterDeviceAclChecks

namespace TDN.Deployments.GrayFirewall_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel

set_option maxRecDepth 1000000

lemma address_inventory_checked (base : Deployment) :
    addressRecordsChecked (deployment base) = true := by rfl

lemma no_workstations : ∀ device ∈ records.components, device.kind ≠ .workstation := by
  native_decide


end TDN.Deployments.GrayFirewall_Shared
