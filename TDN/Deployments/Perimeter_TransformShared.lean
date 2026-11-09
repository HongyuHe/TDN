import TDN.Deployments.Perimeter_TransformCases
import TDN.Deployments.OuterToGray_SharedChecks

namespace TDN.Deployments.Perimeter_TransformShared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_TransformCases

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records inner : ProtectedForwardCase from "../../data/evidence/continuation/Perimeter_TransformShared.json" ["inner"]
load_network_records outer : ProtectedForwardCase from "../../data/evidence/continuation/Perimeter_TransformShared.json" ["outer"]

lemma inner_checks (base : Deployment) : inner.Checks OuterToGray_Shared.records (OuterToGray_Shared.records.deployment base) := by
  exact of_decide_eq_true rfl

lemma outer_checks (base : Deployment) : outer.Checks OuterToGray_Shared.records (OuterToGray_Shared.records.deployment base) := by
  exact of_decide_eq_true rfl

theorem device_Inner_HTTP_reaches_protected_Gray_wire (base : Deployment) :
    (OuterToGray_Shared.records.deployment base).DeviceBoundaryAccepts inner.forward.interface.id .outbound
      ((OuterToGray_Shared.records.deployment base).Observe (inner.packet OuterToGray_Shared.records)) :=
  (checked_case_reaches_configured_wire_header inner OuterToGray_Shared.records (OuterToGray_Shared.records.deployment base) rfl rfl rfl
    OuterToGray_Shared.interface_ids_unique (inner_checks base)).2.2.2.2

theorem device_Outer_ESP_reaches_protected_Black_wire (base : Deployment) :
    (OuterToGray_Shared.records.deployment base).DeviceBoundaryAccepts outer.forward.interface.id .outbound
      ((OuterToGray_Shared.records.deployment base).Observe (outer.packet OuterToGray_Shared.records)) :=
  (checked_case_reaches_configured_wire_header outer OuterToGray_Shared.records (OuterToGray_Shared.records.deployment base) rfl rfl rfl
    OuterToGray_Shared.interface_ids_unique (outer_checks base)).2.2.2.2

end TDN.Deployments.Perimeter_TransformShared
