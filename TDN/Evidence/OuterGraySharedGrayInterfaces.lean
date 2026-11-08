import TDN.Evidence.OuterGraySharedData
import TDN.Evidence.OuterGrayRouteFirst

namespace TDN.Imported.OuterGrayShared
open Compliance Targets Targets.Complete OuterGrayNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data outerGrayInterfaces : List Interface from "../../data/evidence/continuation/OuterGraySharedCases.json" ["outerGrayInterfaces"]

lemma all_applicable_Gray_interfaces_are_listed (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        interface ∈ outerGrayInterfaces := by
  exact of_decide_eq_true rfl

end TDN.Imported.OuterGrayShared
