"""Apply finite post-encryption response checks to an existing guarded execution."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--trace", required=True)
    args = parser.parse_args()
    trace = json.loads(Path(args.trace).read_text())
    count = len(trace["steps"])
    if count == 0 or len(trace["states"]) != count + 1:
        raise ValueError("Complete useful execution required")
    text = """import TDN.Models.BlockRepliesToLocalCiphertext
import MODULE

namespace TDN.Deployments.NAMESPACE
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
      (.network witnessStateFINAL) :=
  EncryptedResponseGuards.network_trace_in_response_system _ _
    positive_delivery_with_early_source_guards

end TDN.Deployments.NAMESPACE
"""
    Path(args.output).write_text(text.replace("MODULE", args.module).replace("NAMESPACE", args.namespace).replace("FINAL", str(count)))


if __name__ == "__main__":
    main()
