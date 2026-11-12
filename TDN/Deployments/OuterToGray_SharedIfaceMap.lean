import TDN.Deployments.OuterToGray_SharedData

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma interface_iface_selection_checked :
    ∀ interface ∈ records.interfaces, records.ifaceIndex interface ∈ records.inventory.ifaces ∧
      records.inventory.ifaceName (records.ifaceIndex interface) = interface.id := by native_decide

end TDN.Deployments.OuterToGray_Shared
