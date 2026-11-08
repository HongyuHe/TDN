import TDN.Evidence.GrayFirewallSharedCheckCommon

namespace TDN.Imported.GrayFirewallShared
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel GrayFirewallNativeChecks
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option synthInstance.maxSize 8192

lemma Gray_interface_012_checked (base : Deployment) :
    GrayInterfaceChecks (deployment base) records.inventory records.pairs
      (records.interfaces[12]'(by decide)) := by
  exact of_decide_eq_true rfl

lemma Gray_permission_012_checked (base : Deployment) :
    GrayPermitChecks (deployment base) records.inventory records.pairs
      (records.interfaces[12]'(by decide)) := by
  exact of_decide_eq_true rfl


end TDN.Imported.GrayFirewallShared
