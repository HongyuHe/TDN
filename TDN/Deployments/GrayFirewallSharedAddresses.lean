import TDN.Deployments.GrayFirewallSharedData
import TDN.Requirements.DeviceAndInterfaceNameTable
import TDN.Requirements.PerimeterDeviceAclChecks

namespace TDN.Deployments.GrayFirewallShared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma address_inventory_checked (base : Deployment) :
    addressRecordsChecked (deployment base) = true := by rfl

lemma no_workstations : ∀ device ∈ records.components, device.kind ≠ .workstation := by
  exact of_decide_eq_true rfl


end TDN.Deployments.GrayFirewallShared
