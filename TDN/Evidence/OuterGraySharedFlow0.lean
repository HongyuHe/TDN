import TDN.Evidence.OuterGraySharedGrayInterfaces

namespace TDN.Imported.OuterGrayShared
open Compliance Targets Targets.Complete OuterGrayNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma gray0_inbound_lookup (base : Deployment) :
    records.RouteFirstMaskLookup base (outerGrayInterfaces[0]'(by decide)) .inbound := by
  exact of_decide_eq_true rfl

lemma gray0_outbound_lookup (base : Deployment) :
    records.RouteFirstMaskLookup base (outerGrayInterfaces[0]'(by decide)) .outbound := by
  exact of_decide_eq_true rfl

end TDN.Imported.OuterGrayShared
