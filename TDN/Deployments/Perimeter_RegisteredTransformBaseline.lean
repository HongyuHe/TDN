import TDN.Deployments.Perimeter_TransformCases
import TDN.Deployments.Perimeter_BaselineData

namespace TDN.Deployments.Perimeter_RegisteredTransformBaseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_TransformCases

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records inner : ProtectedForwardCase from "../../data/evidence/continuation/Perimeter_RegisteredTransformBaseline.json" ["inner"]
load_network_records outer : ProtectedForwardCase from "../../data/evidence/continuation/Perimeter_RegisteredTransformBaseline.json" ["outer"]

lemma interface_ids_unique : InterfaceIDsUnique Perimeter_Baseline.records.interfaces := by
  exact of_decide_eq_true rfl

lemma inner_checks (base : Deployment) : inner.Checks Perimeter_Baseline.records (Perimeter_Baseline.deployment base) := by
  exact of_decide_eq_true rfl

lemma outer_checks (base : Deployment) : outer.Checks Perimeter_Baseline.records (Perimeter_Baseline.deployment base) := by
  exact of_decide_eq_true rfl

theorem device_Inner_HTTP_reaches_protected_Gray_wire (base : Deployment) :
    (Perimeter_Baseline.deployment base).DeviceBoundaryAccepts inner.forward.interface.id .outbound
      ((Perimeter_Baseline.deployment base).Observe (inner.packet Perimeter_Baseline.records)) :=
  (checked_case_reaches_configured_wire_header inner Perimeter_Baseline.records (Perimeter_Baseline.deployment base) rfl rfl rfl
    interface_ids_unique (inner_checks base)).2.2.2.2

theorem device_Outer_ESP_reaches_protected_Black_wire (base : Deployment) :
    (Perimeter_Baseline.deployment base).DeviceBoundaryAccepts outer.forward.interface.id .outbound
      ((Perimeter_Baseline.deployment base).Observe (outer.packet Perimeter_Baseline.records)) :=
  (checked_case_reaches_configured_wire_header outer Perimeter_Baseline.records (Perimeter_Baseline.deployment base) rfl rfl rfl
    interface_ids_unique (outer_checks base)).2.2.2.2

end TDN.Deployments.Perimeter_RegisteredTransformBaseline
