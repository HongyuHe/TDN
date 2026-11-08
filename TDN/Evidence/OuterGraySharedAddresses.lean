import TDN.Evidence.OuterGraySharedData

namespace TDN.Imported.OuterGrayShared
open Compliance Targets Targets.Complete OuterGrayNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma address_inventory_checked (base : Deployment) :
    addressRecordsChecked (records.deployment base) = true := by rfl

end TDN.Imported.OuterGrayShared
