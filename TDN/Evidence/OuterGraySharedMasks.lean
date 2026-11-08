import TDN.Evidence.OuterGraySharedData

namespace TDN.Imported.OuterGrayShared
open Compliance Targets Targets.Complete OuterGrayNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma every_packet_mask_has_an_ordered_allowance :
    ∀ entry ∈ records.masks,
      entry.packet.Covers (Execution.deviceAt records.nativeDevices entry.owner).forwardRules := by exact of_decide_eq_true rfl

lemma pair_and_mask_inventories_nonempty : records.pairs ≠ [] ∧ records.masks ≠ [] := by exact of_decide_eq_true rfl

end TDN.Imported.OuterGrayShared
