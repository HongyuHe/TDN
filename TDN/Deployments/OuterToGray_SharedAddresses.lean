import TDN.Deployments.OuterToGray_SharedData

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma address_inventory_checked (base : Deployment) :
    addressRecordsChecked (records.deployment base) = true := by rfl

end TDN.Deployments.OuterToGray_Shared
