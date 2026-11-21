import TDN.Deployments.DeviceCheckDefaults
import TDN.Import.CompiledDecide
import TDN.Deployments.Perimeter_EncapsulationTestVectors
import TDN.Deployments.OuterToGray_BaselineChecks

namespace TDN.Deployments.Perimeter_TransformBaseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_EncapsulationTestVectors

set_option synthInstance.maxSize 16384
set_option maxRecDepth 1000000

load_network_records inner : ProtectedForwardCase from "../../data/evidence/continuation/Perimeter_TransformBaseline.json" ["inner"]
load_network_records outer : ProtectedForwardCase from "../../data/evidence/continuation/Perimeter_TransformBaseline.json" ["outer"]

lemma inner_checks (base : Deployment) : inner.Checks OuterToGray_Baseline.records (OuterToGray_Baseline.records.deployment base) := by
  close_check_with emptyDeploymentForChecks; native_decide

lemma outer_checks (base : Deployment) : outer.Checks OuterToGray_Baseline.records (OuterToGray_Baseline.records.deployment base) := by
  close_check_with emptyDeploymentForChecks; native_decide

theorem device_inner_http_reaches_protected_gray_wire (base : Deployment) :
    (OuterToGray_Baseline.records.deployment base).DeviceBoundaryAccepts inner.forward.interface.id .outbound
      ((OuterToGray_Baseline.records.deployment base).Observe (inner.packet OuterToGray_Baseline.records)) :=
  (checked_case_reaches_configured_wire_header inner OuterToGray_Baseline.records (OuterToGray_Baseline.records.deployment base) rfl rfl rfl
    OuterToGray_Baseline.interface_ids_unique (inner_checks base)).2.2.2.2

theorem device_outer_esp_reaches_protected_black_wire (base : Deployment) :
    (OuterToGray_Baseline.records.deployment base).DeviceBoundaryAccepts outer.forward.interface.id .outbound
      ((OuterToGray_Baseline.records.deployment base).Observe (outer.packet OuterToGray_Baseline.records)) :=
  (checked_case_reaches_configured_wire_header outer OuterToGray_Baseline.records (OuterToGray_Baseline.records.deployment base) rfl rfl rfl
    OuterToGray_Baseline.interface_ids_unique (outer_checks base)).2.2.2.2

end TDN.Deployments.Perimeter_TransformBaseline
