import TDN.Evidence.BoundaryTransformCases
import TDN.Evidence.BoundaryBaselineData

namespace TDN.Imported.BoundaryRegisteredTransformBaseline
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryTransformCases

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data inner : ProtectedForwardCase from "../../data/evidence/continuation/BoundaryRegisteredTransformBaseline.json" ["inner"]
tdn_data outer : ProtectedForwardCase from "../../data/evidence/continuation/BoundaryRegisteredTransformBaseline.json" ["outer"]

lemma interface_ids_unique : InterfaceIDsUnique BoundaryBaseline.records.interfaces := by
  exact of_decide_eq_true rfl

lemma inner_checks (base : Deployment) : inner.Checks BoundaryBaseline.records (BoundaryBaseline.deployment base) := by
  exact of_decide_eq_true rfl

lemma outer_checks (base : Deployment) : outer.Checks BoundaryBaseline.records (BoundaryBaseline.deployment base) := by
  exact of_decide_eq_true rfl

theorem native_Inner_HTTP_reaches_protected_Gray_wire (base : Deployment) :
    (BoundaryBaseline.deployment base).NativeBoundaryAccepts inner.forward.interface.id .outbound
      ((BoundaryBaseline.deployment base).Observe (inner.packet BoundaryBaseline.records)) :=
  (checked_case_reaches_configured_wire_header inner BoundaryBaseline.records (BoundaryBaseline.deployment base) rfl rfl rfl
    interface_ids_unique (inner_checks base)).2.2.2.2

theorem native_Outer_ESP_reaches_protected_Black_wire (base : Deployment) :
    (BoundaryBaseline.deployment base).NativeBoundaryAccepts outer.forward.interface.id .outbound
      ((BoundaryBaseline.deployment base).Observe (outer.packet BoundaryBaseline.records)) :=
  (checked_case_reaches_configured_wire_header outer BoundaryBaseline.records (BoundaryBaseline.deployment base) rfl rfl rfl
    interface_ids_unique (outer_checks base)).2.2.2.2

end TDN.Imported.BoundaryRegisteredTransformBaseline
