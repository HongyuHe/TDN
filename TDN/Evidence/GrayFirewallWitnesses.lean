import TDN.Evidence.GrayFirewallBaseline
import TDN.Evidence.GrayFirewallShared
import TDN.Evidence.GrayFirewallCasesData

namespace TDN.Imported.GrayFirewallCases
open Compliance Targets Targets.Complete OuterGrayNativeModel NativeForwardEligibility
  BoundaryForwardCases GrayFirewallCasesModel
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option synthInstance.maxSize 8192

lemma positive_samples_checked (base : Deployment) :
    PositiveChecks reply GrayFirewallShared.records (GrayFirewallShared.deployment base) ∧
    PositiveChecks ordinaryIKE GrayFirewallShared.records (GrayFirewallShared.deployment base) ∧
    PositiveChecks replyWithOptions GrayFirewallShared.records (GrayFirewallShared.deployment base) ∧
    PositiveChecks esp GrayFirewallShared.records (GrayFirewallShared.deployment base) ∧
    PositiveChecks udpESP GrayFirewallShared.records (GrayFirewallShared.deployment base) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  all_goals exact of_decide_eq_true rfl

theorem shared_framed_IKE_reply_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewallShared.deployment base).PacketEligibleAt reply.interface .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (reply.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).GrayForwardPermission reply.interface .forward
        ((GrayFirewallShared.deployment base).Observe (reply.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).AcceptsAt reply.interface.id .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (reply.packet GrayFirewallShared.records)) :=
  checked_positive_case reply GrayFirewallShared.records (GrayFirewallShared.deployment base)
    rfl rfl rfl GrayFirewallShared.interface_ids_unique (positive_samples_checked base).1

theorem shared_ordinary_IKE_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewallShared.deployment base).PacketEligibleAt ordinaryIKE.interface .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (ordinaryIKE.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).GrayForwardPermission ordinaryIKE.interface .forward
        ((GrayFirewallShared.deployment base).Observe (ordinaryIKE.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).AcceptsAt ordinaryIKE.interface.id .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (ordinaryIKE.packet GrayFirewallShared.records)) :=
  checked_positive_case ordinaryIKE GrayFirewallShared.records (GrayFirewallShared.deployment base)
    rfl rfl rfl GrayFirewallShared.interface_ids_unique (positive_samples_checked base).2.1

theorem shared_IKE_with_IPv4_options_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewallShared.deployment base).PacketEligibleAt replyWithOptions.interface .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (replyWithOptions.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).GrayForwardPermission replyWithOptions.interface .forward
        ((GrayFirewallShared.deployment base).Observe (replyWithOptions.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).AcceptsAt replyWithOptions.interface.id .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (replyWithOptions.packet GrayFirewallShared.records)) :=
  checked_positive_case replyWithOptions GrayFirewallShared.records (GrayFirewallShared.deployment base)
    rfl rfl rfl GrayFirewallShared.interface_ids_unique (positive_samples_checked base).2.2.1

theorem shared_ESP_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewallShared.deployment base).PacketEligibleAt esp.interface .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (esp.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).GrayForwardPermission esp.interface .forward
        ((GrayFirewallShared.deployment base).Observe (esp.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).AcceptsAt esp.interface.id .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (esp.packet GrayFirewallShared.records)) :=
  checked_positive_case esp GrayFirewallShared.records (GrayFirewallShared.deployment base)
    rfl rfl rfl GrayFirewallShared.interface_ids_unique (positive_samples_checked base).2.2.2.1

theorem shared_UDP_ESP_reply_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewallShared.deployment base).PacketEligibleAt udpESP.interface .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (udpESP.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).GrayForwardPermission udpESP.interface .forward
        ((GrayFirewallShared.deployment base).Observe (udpESP.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).AcceptsAt udpESP.interface.id .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (udpESP.packet GrayFirewallShared.records)) :=
  checked_positive_case udpESP GrayFirewallShared.records (GrayFirewallShared.deployment base)
    rfl rfl rfl GrayFirewallShared.interface_ids_unique (positive_samples_checked base).2.2.2.2

theorem baseline_cross_classification_is_eligible_and_denied (base : Deployment) :
    (BoundaryBaseline.deployment base).PacketEligibleAt baselineCross.interface .inbound .forward
        ((BoundaryBaseline.deployment base).Observe (baselineCross.packet BoundaryBaseline.records)) ∧
      (BoundaryBaseline.deployment base).GrayForwardPermission baselineCross.interface .forward
        ((BoundaryBaseline.deployment base).Observe (baselineCross.packet BoundaryBaseline.records)) ∧
      DifferentClassificationVPNs (BoundaryBaseline.deployment base)
        ((BoundaryBaseline.deployment base).Observe (baselineCross.packet BoundaryBaseline.records)) ∧
      ¬ (BoundaryBaseline.deployment base).AcceptsAt baselineCross.interface.id .inbound .forward
        ((BoundaryBaseline.deployment base).Observe (baselineCross.packet BoundaryBaseline.records)) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · apply checked_forward_context_is_eligible baselineCross BoundaryBaseline.records
      (BoundaryBaseline.deployment base) rfl rfl .inbound
    exact of_decide_eq_true rfl
  · intro _
    exact of_decide_eq_true rfl
  · apply checked_classification_pair _ _ baselineCrossSource baselineCrossDestination
    exact of_decide_eq_true rfl
  · apply checked_forward_hook_is_denied
    exact of_decide_eq_true rfl

theorem shared_cross_classification_is_eligible_and_denied (base : Deployment) :
    (GrayFirewallShared.deployment base).PacketEligibleAt sharedCross.interface .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (sharedCross.packet GrayFirewallShared.records)) ∧
      (GrayFirewallShared.deployment base).GrayForwardPermission sharedCross.interface .forward
        ((GrayFirewallShared.deployment base).Observe (sharedCross.packet GrayFirewallShared.records)) ∧
      DifferentClassificationVPNs (GrayFirewallShared.deployment base)
        ((GrayFirewallShared.deployment base).Observe (sharedCross.packet GrayFirewallShared.records)) ∧
      ¬ (GrayFirewallShared.deployment base).AcceptsAt sharedCross.interface.id .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (sharedCross.packet GrayFirewallShared.records)) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · apply checked_forward_context_is_eligible sharedCross GrayFirewallShared.records
      (GrayFirewallShared.deployment base) rfl rfl .inbound
    exact of_decide_eq_true rfl
  · intro _
    exact of_decide_eq_true rfl
  · apply checked_classification_pair _ _ sharedCrossSource sharedCrossDestination
    exact of_decide_eq_true rfl
  · apply checked_forward_hook_is_denied
    exact of_decide_eq_true rfl

theorem shared_malformed_IKE_is_eligible_and_denied (base : Deployment) :
    (GrayFirewallShared.deployment base).PacketEligibleAt malformedIKE.interface .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (malformedIKE.packet GrayFirewallShared.records)) ∧
      ¬ (GrayFirewallShared.deployment base).AcceptsAt malformedIKE.interface.id .inbound .forward
        ((GrayFirewallShared.deployment base).Observe (malformedIKE.packet GrayFirewallShared.records)) := by
  constructor
  · apply checked_forward_context_is_eligible malformedIKE GrayFirewallShared.records
      (GrayFirewallShared.deployment base) rfl rfl .inbound
    exact of_decide_eq_true rfl
  · apply checked_forward_hook_is_denied
    exact of_decide_eq_true rfl

end TDN.Imported.GrayFirewallCases
