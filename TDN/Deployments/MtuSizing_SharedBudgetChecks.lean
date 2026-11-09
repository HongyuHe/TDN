import TDN.Deployments.MtuSizing_SharedData
import TDN.Deployments.MtuSizing_Application

namespace TDN.Deployments.MtuSizing_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records
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

end TDN.Deployments.MtuSizing_Shared
