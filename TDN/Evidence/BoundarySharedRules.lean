import TDN.Evidence.BoundarySharedData
import TDN.Targets.BoundaryNativeChecks

namespace TDN.Imported.BoundaryShared
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma encryption_rules_checked (base : Deployment) :
    ∀ interface ∈ (deployment base).interfaces,
      ∀ device ∈ (deployment base).devices, interface.device = device.id →
        (CryptographicBoundary device interface →
          BoundaryProtocolChecks (deployment base) records.inventory interface) ∧
        ((device.layer = some .outer ∧ interface.zone = .black) →
          BoundaryPeerChecks (deployment base) records.inventory interface peers) ∧
        ((device.layer = some .inner ∧ interface.zone = .red) →
          BoundaryRedChecks (deployment base) records.inventory interface redEndpoints) := by
  exact of_decide_eq_true rfl

end TDN.Imported.BoundaryShared
