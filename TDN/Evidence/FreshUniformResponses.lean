import TDN.Import.Command
import TDN.Semantics.UniformResponseRegions
import TDN.Semantics.HistoricalResponses
import TDN.Evidence.FreshEncryptedResponseGuards

namespace TDN.Imported.Family444V13
set_option maxRecDepth 100000
set_option maxHeartbeats 0

tdn_data uniformResponseOwners : List Nat from "../../data/evidence/FreshUniformResponses.json" ["TDN.Imported.Family444V13.uniformResponseOwners"]

lemma uniform_response_regions_checked :
    UniformResponseRegions.FiniteUniform devices ports uniformResponseOwners := by
  unfold UniformResponseRegions.FiniteUniform
  decide

lemma response_component_inventory_complete :
    ∀ port ∈ ports, port.owner ∈ uniformResponseOwners ∨
      ∃ guard ∈ responseSourceGuards, port.owner = guard.1 := by decide

theorem all_component_copied_responses_keep_stack
    {before after : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (UniformResponseRegions.responseConfig responseData uniformResponseOwners)).MTr
      (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe responseData before) :
    Execution.StackInvariant config layout after :=
  UniformResponseRegions.all_component_response_executions_preserve_stack responseData
    uniformResponseOwners local_stack_conditions all_source_output_reply_pairs_checked
    all_input_interfaces_covered response_default_checks locally_encrypted_response_denial
    uniform_response_regions_checked run initial

theorem useful_delivery_with_all_component_responses :
    (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (UniformResponseRegions.responseConfig responseData uniformResponseOwners)).MTr
      (.network witnessState0) (witnessActions.map KernelResponses.Action.network)
      (.network witnessState39) :=
  EncryptedResponseGuards.network_trace_in_response_system _ _
    positive_delivery_with_early_source_guards

def responseHistoryConfig :=
  HistoricalResponses.responseConfig
    (UniformResponseRegions.responseConfig responseData uniformResponseOwners)

theorem all_retained_packet_responses_keep_stack
    {before after : HistoricalResponses.State Execution.State}
    {actions : List (KernelResponses.Action (HistoricalResponses.Action Execution.Action))}
    (run : (KernelResponses.lts
      (HistoricalResponses.lts (GuardedResponseNetwork.network responseData))
      responseHistoryConfig).MTr (.network before) actions (.network after))
    (initial : HistoricalResponses.Safe (GuardedResponseNetwork.Safe responseData) before) :
    Execution.StackInvariant config layout after.current :=
  (HistoricalResponses.all_historical_responses_preserve_safety
    (GuardedResponseNetwork.network responseData)
    (UniformResponseRegions.responseConfig responseData uniformResponseOwners)
    (GuardedResponseNetwork.Safe responseData)
    (GuardedResponseNetwork.network_preserves_safe responseData local_stack_conditions)
    (UniformResponseRegions.reply_preserves_safe responseData uniformResponseOwners
      local_stack_conditions all_source_output_reply_pairs_checked all_input_interfaces_covered
      response_default_checks locally_encrypted_response_denial uniform_response_regions_checked)
    run initial).1.1

theorem useful_delivery_with_retained_packet_contexts :
    ∃ saved, (KernelResponses.lts
      (HistoricalResponses.lts (GuardedResponseNetwork.network responseData))
      responseHistoryConfig).MTr (.network ⟨witnessState0, []⟩)
      ((witnessActions.map HistoricalResponses.Action.network).map KernelResponses.Action.network)
      (.network ⟨witnessState39, saved⟩) := by
  obtain ⟨saved, run⟩ := HistoricalResponses.lift_network_trace
    (GuardedResponseNetwork.network responseData) positive_delivery_with_early_source_guards []
  exact ⟨saved, EncryptedResponseGuards.network_trace_in_response_system _ _ run⟩

end TDN.Imported.Family444V13
