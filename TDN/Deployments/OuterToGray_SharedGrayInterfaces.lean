import TDN.Deployments.OuterToGray_SharedData
import TDN.Deployments.OuterToGray_PreEncapRouteLookup

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records outerGrayInterfaces : List Interface from "../../data/evidence/continuation/OuterToGray_SharedCases.json" ["outerGrayInterfaces"]

lemma all_applicable_Gray_interfaces_are_listed (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        interface ∈ outerGrayInterfaces := by
  exact of_decide_eq_true rfl

end TDN.Deployments.OuterToGray_Shared
