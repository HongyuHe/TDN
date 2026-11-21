import TDN.Deployments.DeviceCheckDefaults
import TDN.Deployments.GrayFirewall_Baseline
import TDN.Deployments.GrayFirewall_Shared
import TDN.Deployments.GrayFirewall_TestVectorData

namespace TDN.Deployments.GrayFirewall_TestVectors
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel DeviceForwardingEligibility
  Perimeter_ForwardingTestVectors GrayFirewall_TestVectorChecks
set_option maxRecDepth 1000000
set_option synthInstance.maxSize 8192

lemma positive_samples_checked (base : Deployment) :
    PositiveChecks reply GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base) ∧
    PositiveChecks ordinaryIKE GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base) ∧
    PositiveChecks replyWithOptions GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base) ∧
    PositiveChecks esp GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base) ∧
    PositiveChecks udpESP GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  all_goals close_check_with emptyDeploymentForChecks; native_decide

theorem shared_framed_ike_reply_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewall_Shared.deployment base).PacketEligibleAt reply.interface .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (reply.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).GrayForwardPermission reply.interface .forward
        ((GrayFirewall_Shared.deployment base).Observe (reply.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).PermitsAtHook reply.interface.id .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (reply.packet GrayFirewall_Shared.records)) :=
  checked_positive_case reply GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base)
    rfl rfl rfl GrayFirewall_Shared.interface_ids_unique (positive_samples_checked base).1

theorem shared_ordinary_ike_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewall_Shared.deployment base).PacketEligibleAt ordinaryIKE.interface .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (ordinaryIKE.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).GrayForwardPermission ordinaryIKE.interface .forward
        ((GrayFirewall_Shared.deployment base).Observe (ordinaryIKE.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).PermitsAtHook ordinaryIKE.interface.id .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (ordinaryIKE.packet GrayFirewall_Shared.records)) :=
  checked_positive_case ordinaryIKE GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base)
    rfl rfl rfl GrayFirewall_Shared.interface_ids_unique (positive_samples_checked base).2.1

theorem shared_ike_with_ipv4_options_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewall_Shared.deployment base).PacketEligibleAt replyWithOptions.interface .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (replyWithOptions.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).GrayForwardPermission replyWithOptions.interface .forward
        ((GrayFirewall_Shared.deployment base).Observe (replyWithOptions.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).PermitsAtHook replyWithOptions.interface.id .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (replyWithOptions.packet GrayFirewall_Shared.records)) :=
  checked_positive_case replyWithOptions GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base)
    rfl rfl rfl GrayFirewall_Shared.interface_ids_unique (positive_samples_checked base).2.2.1

theorem shared_esp_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewall_Shared.deployment base).PacketEligibleAt esp.interface .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (esp.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).GrayForwardPermission esp.interface .forward
        ((GrayFirewall_Shared.deployment base).Observe (esp.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).PermitsAtHook esp.interface.id .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (esp.packet GrayFirewall_Shared.records)) :=
  checked_positive_case esp GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base)
    rfl rfl rfl GrayFirewall_Shared.interface_ids_unique (positive_samples_checked base).2.2.2.1

theorem shared_udp_esp_reply_is_eligible_and_accepted (base : Deployment) :
    (GrayFirewall_Shared.deployment base).PacketEligibleAt udpESP.interface .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (udpESP.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).GrayForwardPermission udpESP.interface .forward
        ((GrayFirewall_Shared.deployment base).Observe (udpESP.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).PermitsAtHook udpESP.interface.id .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (udpESP.packet GrayFirewall_Shared.records)) :=
  checked_positive_case udpESP GrayFirewall_Shared.records (GrayFirewall_Shared.deployment base)
    rfl rfl rfl GrayFirewall_Shared.interface_ids_unique (positive_samples_checked base).2.2.2.2

theorem baseline_cross_classification_is_eligible_and_denied (base : Deployment) :
    (Perimeter_Baseline.deployment base).PacketEligibleAt baselineCross.interface .inbound .forward
        ((Perimeter_Baseline.deployment base).Observe (baselineCross.packet Perimeter_Baseline.records)) ∧
      (Perimeter_Baseline.deployment base).GrayForwardPermission baselineCross.interface .forward
        ((Perimeter_Baseline.deployment base).Observe (baselineCross.packet Perimeter_Baseline.records)) ∧
      DifferentClassificationVPNs (Perimeter_Baseline.deployment base)
        ((Perimeter_Baseline.deployment base).Observe (baselineCross.packet Perimeter_Baseline.records)) ∧
      ¬ (Perimeter_Baseline.deployment base).PermitsAtHook baselineCross.interface.id .inbound .forward
        ((Perimeter_Baseline.deployment base).Observe (baselineCross.packet Perimeter_Baseline.records)) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · apply checked_forward_context_is_eligible baselineCross Perimeter_Baseline.records
      (Perimeter_Baseline.deployment base) rfl rfl .inbound
    close_check_with emptyDeploymentForChecks; native_decide
  · intro _
    close_check_with emptyDeploymentForChecks; native_decide
  · apply checked_classification_pair _ _ baselineCrossSource baselineCrossDestination
    close_check_with emptyDeploymentForChecks; native_decide
  · apply checked_forward_hook_is_denied
    close_check_with emptyDeploymentForChecks; native_decide

theorem shared_cross_classification_is_eligible_and_denied (base : Deployment) :
    (GrayFirewall_Shared.deployment base).PacketEligibleAt sharedCross.interface .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (sharedCross.packet GrayFirewall_Shared.records)) ∧
      (GrayFirewall_Shared.deployment base).GrayForwardPermission sharedCross.interface .forward
        ((GrayFirewall_Shared.deployment base).Observe (sharedCross.packet GrayFirewall_Shared.records)) ∧
      DifferentClassificationVPNs (GrayFirewall_Shared.deployment base)
        ((GrayFirewall_Shared.deployment base).Observe (sharedCross.packet GrayFirewall_Shared.records)) ∧
      ¬ (GrayFirewall_Shared.deployment base).PermitsAtHook sharedCross.interface.id .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (sharedCross.packet GrayFirewall_Shared.records)) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · apply checked_forward_context_is_eligible sharedCross GrayFirewall_Shared.records
      (GrayFirewall_Shared.deployment base) rfl rfl .inbound
    close_check_with emptyDeploymentForChecks; native_decide
  · intro _
    close_check_with emptyDeploymentForChecks; native_decide
  · apply checked_classification_pair _ _ sharedCrossSource sharedCrossDestination
    close_check_with emptyDeploymentForChecks; native_decide
  · apply checked_forward_hook_is_denied
    close_check_with emptyDeploymentForChecks; native_decide

theorem shared_malformed_ike_is_eligible_and_denied (base : Deployment) :
    (GrayFirewall_Shared.deployment base).PacketEligibleAt malformedIKE.interface .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (malformedIKE.packet GrayFirewall_Shared.records)) ∧
      ¬ (GrayFirewall_Shared.deployment base).PermitsAtHook malformedIKE.interface.id .inbound .forward
        ((GrayFirewall_Shared.deployment base).Observe (malformedIKE.packet GrayFirewall_Shared.records)) := by
  constructor
  · apply checked_forward_context_is_eligible malformedIKE GrayFirewall_Shared.records
      (GrayFirewall_Shared.deployment base) rfl rfl .inbound
    close_check_with emptyDeploymentForChecks; native_decide
  · apply checked_forward_hook_is_denied
    close_check_with emptyDeploymentForChecks; native_decide

end TDN.Deployments.GrayFirewall_TestVectors
