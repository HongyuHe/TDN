import TDN.Evidence.BoundarySharedData
import TDN.Targets.BoundaryNativeChecks

namespace TDN.Imported.BoundaryShared
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma control_observations_checked (base : Deployment) :
    BoundaryControlObservationChecks (deployment base) controls := by
  exact of_decide_eq_true rfl

lemma firewall_rules_checked (base : Deployment) :
    ∀ interface ∈ (deployment base).interfaces,
      ∀ device ∈ (deployment base).devices, interface.device = device.id →
        device.kind = .outerFirewall →
          (deployment base).IsLayer (localOuter firewalls device.id) .outer ∧
            BoundaryFirewallChecks (deployment base) records.inventory controls interface
              (localOuter firewalls device.id) (firewallInternal.contains interface.id) := by
  exact of_decide_eq_true rfl

end TDN.Imported.BoundaryShared
