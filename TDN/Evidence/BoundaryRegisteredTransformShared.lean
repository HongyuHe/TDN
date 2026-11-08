import TDN.Evidence.BoundaryTransformCases
import TDN.Evidence.BoundarySharedData

namespace TDN.Imported.BoundaryRegisteredTransformShared
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryTransformCases

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data inner : ProtectedForwardCase from "../../data/evidence/continuation/BoundaryRegisteredTransformShared.json" ["inner"]
tdn_data outer : ProtectedForwardCase from "../../data/evidence/continuation/BoundaryRegisteredTransformShared.json" ["outer"]

lemma interface_ids_unique : InterfaceIDsUnique BoundaryShared.records.interfaces := by
  exact of_decide_eq_true rfl

lemma inner_checks (base : Deployment) : inner.Checks BoundaryShared.records (BoundaryShared.deployment base) := by
  exact of_decide_eq_true rfl

lemma outer_checks (base : Deployment) : outer.Checks BoundaryShared.records (BoundaryShared.deployment base) := by
  exact of_decide_eq_true rfl

theorem native_Inner_HTTP_reaches_protected_Gray_wire (base : Deployment) :
    (BoundaryShared.deployment base).NativeBoundaryAccepts inner.forward.interface.id .outbound
      ((BoundaryShared.deployment base).Observe (inner.packet BoundaryShared.records)) :=
  (checked_case_reaches_configured_wire_header inner BoundaryShared.records (BoundaryShared.deployment base) rfl rfl rfl
    interface_ids_unique (inner_checks base)).2.2.2.2

theorem native_Outer_ESP_reaches_protected_Black_wire (base : Deployment) :
    (BoundaryShared.deployment base).NativeBoundaryAccepts outer.forward.interface.id .outbound
      ((BoundaryShared.deployment base).Observe (outer.packet BoundaryShared.records)) :=
  (checked_case_reaches_configured_wire_header outer BoundaryShared.records (BoundaryShared.deployment base) rfl rfl rfl
    interface_ids_unique (outer_checks base)).2.2.2.2

end TDN.Imported.BoundaryRegisteredTransformShared
