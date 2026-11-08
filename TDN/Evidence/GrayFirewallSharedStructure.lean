import TDN.Evidence.GrayFirewallSharedData
import TDN.Targets.FiniteInventoryNames
import TDN.Targets.BoundaryNativeChecks

namespace TDN.Imported.GrayFirewallShared
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma iface_names_are_nodup : records.ifaceNames.Nodup := by
  exact of_decide_eq_true rfl

lemma interface_ids_unique : InterfaceIDsUnique records.interfaces :=
  interface_ids_unique_from_nodup records.interfaces
    (by change records.ifaceNames.Nodup; exact iface_names_are_nodup)

lemma native_structure_checked (base : Deployment) :
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


end TDN.Imported.GrayFirewallShared
