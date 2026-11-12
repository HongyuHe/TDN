import TDN.Import.NativeDecide
import TDN.Deployments.OuterToGray_SharedIdentifiers

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma device_structure_checked (base : Deployment) :
    ProcessingStructuralChecks (records.deployment base) records.inventory := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · unfold_check_parameters; native_decide
  · unfold_check_parameters; native_decide
  · unfold_check_parameters; native_decide
  · unfold_check_parameters; native_decide
  · exact indexed_iface_names_unique records.ifaceNames records.nativeIfaces.length rfl iface_names_are_nodup
  · unfold_check_parameters; native_decide
  · native_decide
  · native_decide
  · native_decide

end TDN.Deployments.OuterToGray_Shared
