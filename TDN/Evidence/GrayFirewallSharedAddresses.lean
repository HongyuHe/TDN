import TDN.Evidence.GrayFirewallSharedData
import TDN.Targets.FiniteInventoryNames
import TDN.Targets.BoundaryNativeChecks

namespace TDN.Imported.GrayFirewallShared
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma address_inventory_checked (base : Deployment) :
    addressRecordsChecked (deployment base) = true := by rfl

lemma no_workstations : ∀ device ∈ records.components, device.kind ≠ .workstation := by
  exact of_decide_eq_true rfl


end TDN.Imported.GrayFirewallShared
