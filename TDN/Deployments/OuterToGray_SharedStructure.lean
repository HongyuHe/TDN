import TDN.Deployments.OuterToGray_SharedIdentifiers

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma device_structure_checked (base : Deployment) :
    ProcessingStructuralChecks (records.deployment base) records.inventory := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact indexed_iface_names_unique records.ifaceNames records.nativeIfaces.length rfl iface_names_are_nodup
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl

end TDN.Deployments.OuterToGray_Shared
