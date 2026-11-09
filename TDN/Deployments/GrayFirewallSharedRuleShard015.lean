import TDN.Deployments.GrayFirewallSharedCheckCommon

namespace TDN.Deployments.GrayFirewallShared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel GrayFirewallIptablesChecks
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option synthInstance.maxSize 8192

lemma Gray_interface_015_checked (base : Deployment) :
    GrayInterfaceChecks (deployment base) records.inventory records.pairs
      (records.interfaces[15]'(by decide)) := by
  exact of_decide_eq_true rfl

lemma Gray_permission_015_checked (base : Deployment) :
    GrayPermitChecks (deployment base) records.inventory records.pairs
      (records.interfaces[15]'(by decide)) := by
  exact of_decide_eq_true rfl


end TDN.Deployments.GrayFirewallShared
