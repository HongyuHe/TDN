import TDN.Evidence.SizingBaselineData
import TDN.Evidence.PacketSizingApplication

namespace TDN.Imported.SizingBaseline
open Compliance Targets Targets.Complete OuterGrayNativeModel PacketSizingRecords
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma captured_size_checks : SizeRecordChecks records installations roles := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  all_goals exact of_decide_eq_true rfl

lemma captured_mtu_checks : RoleMtuChecks roles := by
  exact of_decide_eq_true rfl

lemma captured_sizing_inventory {Key : Type} (codec : IPsecFrameEncoding.Codec Key) (base : Deployment) :
    SizingInventoryChecks
      (completeDeployment records installations linkPolicies codec networks attachments services base)
      records.ifaceName (settings roles) := by
  exact of_decide_eq_true rfl

lemma captured_route_targets : ∀ route ∈ records.routes, route.egress ∈ records.inventory.ifaces := by
  exact of_decide_eq_true rfl

end TDN.Imported.SizingBaseline
