"""Apply uniform-region response checks to every remaining inventoried component."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    for name in ["report", "module", "namespace", "output", "trace", "scope-report"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text())
    trace = json.loads(Path(args.trace).read_text())
    count = len(trace["steps"])
    if count == 0 or len(trace["states"]) != count + 1:
        raise ValueError("Complete positive trace required")
    names = sorted(set(report["device_ids"]) - set(report["early_source_guards"]))
    owners = [report["device_ids"][name] for name in names]
    if not owners:
        raise ValueError("No remaining component inventory")
    text = """import TDN.Semantics.UniformResponseRegions
import TDN.Semantics.HistoricalResponses
import MODULE

namespace TDN.Imported.NAMESPACE
set_option maxRecDepth 100000
set_option maxHeartbeats 0

def uniformResponseOwners : List Nat := OWNERS

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
      (.network witnessStateFINAL) :=
  EncryptedResponseGuards.network_trace_in_response_system _ _
    positive_delivery_with_early_source_guards

def responseHistoryConfig :=
  HistoricalResponses.responseConfig
    (UniformResponseRegions.responseConfig responseData uniformResponseOwners)

/-- Delayed error handling may select any saved packet context. All retained
contexts satisfy the same fixed-configuration local emission checks. -/
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
      (.network ⟨witnessStateFINAL, saved⟩) := by
  obtain ⟨saved, run⟩ := HistoricalResponses.lift_network_trace
    (GuardedResponseNetwork.network responseData) positive_delivery_with_early_source_guards []
  exact ⟨saved, EncryptedResponseGuards.network_trace_in_response_system _ _ run⟩

end TDN.Imported.NAMESPACE
"""
    Path(args.output).write_text(text.replace("MODULE", args.module).replace("NAMESPACE", args.namespace)
                                 .replace("OWNERS", str(owners)).replace("FINAL", str(count)))
    data = {"execution_report": args.report,
            "execution_report_sha256": hashlib.sha256(Path(args.report).read_bytes()).hexdigest(),
            "uniform_components": names, "guarded_components": sorted(report["early_source_guards"]),
            "scope": [
                "Every actual port owner is covered by a source-guarded gateway or a checked uniform protection region.",
                "Uniform-region components may generate copied-byte responses at any non-dropped phase.",
                "Encrypted gateway quotes and pre-encryption gateway processing use their separate checked conditions.",
                "The fixed-configuration model retains byte-protection provenance and kernel response return-to-source semantics as implementation contracts.",
                "Asynchronous references to saved earlier contexts are included in the checked history extension; fragment-byte composition remains separately recorded."]}
    Path(args.scope_report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"uniform_components": names, "all_observed_components": len(report["device_ids"])}))


if __name__ == "__main__":
    main()
