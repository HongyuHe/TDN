import TDN.Deployments.OuterToGray_SharedData

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma device_program_atoms_checked :
    ∀ iface ∈ records.inventory.ifaces, DeviceProgramAtoms records.inventory iface := by native_decide

end TDN.Deployments.OuterToGray_Shared
