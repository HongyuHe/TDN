import TDN.Evidence.BoundaryTransformCases
import TDN.Evidence.OuterGraySharedChecks

namespace TDN.Imported.BoundaryTransformShared
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryTransformCases

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data inner : ProtectedForwardCase from "../../data/evidence/continuation/BoundaryTransformShared.json" ["inner"]
tdn_data outer : ProtectedForwardCase from "../../data/evidence/continuation/BoundaryTransformShared.json" ["outer"]

lemma inner_checks (base : Deployment) : inner.Checks OuterGrayShared.records (OuterGrayShared.records.deployment base) := by
  exact of_decide_eq_true rfl

lemma outer_checks (base : Deployment) : outer.Checks OuterGrayShared.records (OuterGrayShared.records.deployment base) := by
  exact of_decide_eq_true rfl

theorem native_Inner_HTTP_reaches_protected_Gray_wire (base : Deployment) :
    (OuterGrayShared.records.deployment base).NativeBoundaryAccepts inner.forward.interface.id .outbound
      ((OuterGrayShared.records.deployment base).Observe (inner.packet OuterGrayShared.records)) :=
  (checked_case_reaches_configured_wire_header inner OuterGrayShared.records (OuterGrayShared.records.deployment base) rfl rfl rfl
    OuterGrayShared.interface_ids_unique (inner_checks base)).2.2.2.2

theorem native_Outer_ESP_reaches_protected_Black_wire (base : Deployment) :
    (OuterGrayShared.records.deployment base).NativeBoundaryAccepts outer.forward.interface.id .outbound
      ((OuterGrayShared.records.deployment base).Observe (outer.packet OuterGrayShared.records)) :=
  (checked_case_reaches_configured_wire_header outer OuterGrayShared.records (OuterGrayShared.records.deployment base) rfl rfl rfl
    OuterGrayShared.interface_ids_unique (outer_checks base)).2.2.2.2

end TDN.Imported.BoundaryTransformShared
