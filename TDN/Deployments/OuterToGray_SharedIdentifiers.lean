import TDN.Deployments.OuterToGray_SharedData
import TDN.Requirements.DeviceAndInterfaceNameTable

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma iface_names_are_nodup : records.ifaceNames.Nodup := by exact of_decide_eq_true rfl

lemma interface_ids_unique : InterfaceIDsUnique records.interfaces :=
  interface_ids_unique_from_nodup records.interfaces (by change records.ifaceNames.Nodup; exact iface_names_are_nodup)

end TDN.Deployments.OuterToGray_Shared
