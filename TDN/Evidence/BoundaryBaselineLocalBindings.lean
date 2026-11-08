import TDN.Evidence.BoundaryBaselineData

namespace TDN.Imported.BoundaryBaseline
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma recorded_firewalls_are_attached_to_their_local_Outers :
    ∀ binding ∈ firewalls,
      ∃ first ∈ records.inventory.ifaces,
        records.inventory.componentName (records.inventory.configuration.ip.owner first) = binding.firewall ∧
        records.inventory.configuration.ip.interfaceName first = "inside" ∧
        ∃ second ∈ records.inventory.ifaces,
          records.inventory.componentName (records.inventory.configuration.ip.owner second) = binding.outer ∧
          records.inventory.configuration.ip.interfaceName second = "black" ∧
          records.inventory.configuration.physicalLink first second := by
  exact of_decide_eq_true rfl

end TDN.Imported.BoundaryBaseline
