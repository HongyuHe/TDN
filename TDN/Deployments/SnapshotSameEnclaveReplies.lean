import TDN.Import.SnapshotLoader
import TDN.Models.UniformStackDeviceReplies
import TDN.Models.DelayedPacketReplySafety
import TDN.Deployments.SnapshotEncryptedResponseGuards

namespace TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
set_option maxRecDepth 100000
set_option maxHeartbeats 0

load_network_records uniformResponseOwners : List Nat from "../../data/evidence/SnapshotSameEnclaveReplies.json" ["TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13.uniformResponseOwners"]

lemma uniform_response_regions_checked :
    UniformResponseRegions.TableDrivenUniform devices ifaces uniformResponseOwners := by
  unfold UniformResponseRegions.TableDrivenUniform
  decide

lemma response_component_inventory_complete :
    ∀ iface ∈ ifaces, iface.owner ∈ uniformResponseOwners ∨
      ∃ guard ∈ responseSourceGuards, iface.owner = guard.1 := by decide

theorem all_component_copied_responses_keep_stack
    {before after : DataPlaneForwarding.State} {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network responseData)
      (UniformResponseRegions.responseConfig responseData uniformResponseOwners)).MTr
      (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe responseData before) :
    DataPlaneForwarding.EncapStackConsistent config expectedEncapStack after :=
  UniformResponseRegions.all_component_response_traces_preserve_stack responseData
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
    {before after : HistoricalResponses.State DataPlaneForwarding.State}
    {actions : List (KernelResponses.Action (HistoricalResponses.Action DataPlaneForwarding.Action))}
    (run : (KernelResponses.lts
      (HistoricalResponses.lts (GuardedResponseNetwork.network responseData))
      responseHistoryConfig).MTr (.network before) actions (.network after))
    (initial : HistoricalResponses.Safe (GuardedResponseNetwork.Safe responseData) before) :
    DataPlaneForwarding.EncapStackConsistent config expectedEncapStack after.current :=
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

end TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13
