import TDN.Deployments.OuterToGray_SharedData

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma every_packet_mask_has_an_ordered_allowance :
    ∀ entry ∈ records.masks,
      entry.packet.IsPermittedByAclChain (DataPlaneForwarding.deviceAt records.nativeDevices entry.owner).forwardRules := by exact of_decide_eq_true rfl

lemma pair_and_mask_inventories_nonempty : records.pairs ≠ [] ∧ records.masks ≠ [] := by exact of_decide_eq_true rfl

end TDN.Deployments.OuterToGray_Shared
