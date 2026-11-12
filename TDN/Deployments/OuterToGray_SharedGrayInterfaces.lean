import TDN.Import.NativeDecide
import TDN.Deployments.OuterToGray_SharedData
import TDN.Deployments.OuterToGray_PreEncapRouteLookup

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records outerGrayInterfaces : List Interface from "../../data/evidence/continuation/OuterToGray_SharedCases.json" ["outerGrayInterfaces"]

lemma all_applicable_Gray_interfaces_are_listed (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        interface ∈ outerGrayInterfaces := by
  unfold_check_parameters; native_decide

end TDN.Deployments.OuterToGray_Shared
