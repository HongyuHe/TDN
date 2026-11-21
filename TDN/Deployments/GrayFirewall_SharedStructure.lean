import TDN.Import.CompiledDecide
import TDN.Deployments.GrayFirewall_SharedData
import TDN.Requirements.DeviceAndInterfaceNameTable
import TDN.Requirements.PerimeterDeviceAclChecks

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.GrayFirewall_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel

set_option maxRecDepth 1000000

lemma iface_names_are_nodup : records.ifaceNames.Nodup := by
  native_decide

lemma interface_ids_unique : InterfaceIDsUnique records.interfaces :=
  interface_ids_unique_from_nodup records.interfaces
    (by change records.ifaceNames.Nodup; exact iface_names_are_nodup)

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


end TDN.Deployments.GrayFirewall_Shared
