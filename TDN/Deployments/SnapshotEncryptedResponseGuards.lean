import TDN.Models.BlockRepliesToLocalCiphertext
import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13_ReplyForwarding

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
set_option maxRecDepth 100000
set_option maxHeartbeats 0

lemma locally_encrypted_response_rules_checked :
    EncryptedResponseGuards.TableDrivenDeny devices := by
  unfold EncryptedResponseGuards.TableDrivenDeny
  decide

lemma locally_encrypted_response_denial : EncryptedResponseGuards.LocalDeny config :=
  EncryptedResponseGuards.table_driven_deny_sound devices ifaces routes links switches
    locally_encrypted_response_rules_checked

theorem gateway_pre_and_post_encryption_responses_keep_stack
    {before after : DataPlaneForwarding.State} {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (EncryptedResponseGuards.combinedConfig responseData)).MTr
      (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe responseData before) :
    DataPlaneForwarding.EncapStackConsistent config expectedEncapStack after :=
  EncryptedResponseGuards.combined_traces_preserve_stack responseData
    local_stack_conditions all_source_output_reply_pairs_checked all_input_interfaces_covered
    response_default_checks locally_encrypted_response_denial run initial

theorem useful_delivery_in_combined_response_system :
    (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (EncryptedResponseGuards.combinedConfig responseData)).MTr
      (.network witnessState0) (witnessActions.map KernelResponses.Action.network)
      (.network witnessState39) :=
  EncryptedResponseGuards.network_trace_in_response_system _ _
    positive_delivery_with_early_source_guards

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
