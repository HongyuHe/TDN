import TDN.Semantics.EncryptedResponseGuards
import TDN.Evidence.FreshFamily444V13ResponseExecution

namespace TDN.Imported.Family444V13
set_option maxRecDepth 100000
set_option maxHeartbeats 0

lemma locally_encrypted_response_rules_checked :
    EncryptedResponseGuards.FiniteDeny devices := by
  unfold EncryptedResponseGuards.FiniteDeny
  decide

lemma locally_encrypted_response_denial : EncryptedResponseGuards.LocalDeny config :=
  EncryptedResponseGuards.finite_deny_sound devices ports routes links switches
    locally_encrypted_response_rules_checked

theorem gateway_pre_and_post_encryption_responses_keep_stack
    {before after : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (EncryptedResponseGuards.combinedConfig responseData)).MTr
      (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe responseData before) :
    Execution.StackInvariant config layout after :=
  EncryptedResponseGuards.combined_executions_preserve_stack responseData
    local_stack_conditions all_source_output_reply_pairs_checked all_input_interfaces_covered
    response_default_checks locally_encrypted_response_denial run initial

theorem useful_delivery_in_combined_response_system :
    (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (EncryptedResponseGuards.combinedConfig responseData)).MTr
      (.network witnessState0) (witnessActions.map KernelResponses.Action.network)
      (.network witnessState39) :=
  EncryptedResponseGuards.network_trace_in_response_system _ _
    positive_delivery_with_early_source_guards

end TDN.Imported.Family444V13
