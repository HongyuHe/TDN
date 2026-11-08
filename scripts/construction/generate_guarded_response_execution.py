"""Apply the generic guarded response execution theorem and retain useful paths."""
import argparse
import json
from pathlib import Path

from generate_execution_witness import packet_lean
from import_snapshot import lean_list
from validate_evidence import require


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("trace")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--guard-module", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    trace = json.loads(Path(args.trace).read_text())
    count = len(trace["steps"])
    require(count > 0 and len(trace["states"]) == count + 1, "Incomplete useful trace")
    lines = [
        "import TDN.Semantics.GuardedResponseNetwork",
        "import " + args.guard_module,
        "",
        "namespace TDN.Imported." + args.namespace,
        "open Execution",
        "set_option maxRecDepth 100000",
        "set_option maxHeartbeats 0",
        "",
        "def responseData : GuardedResponseNetwork.Data :=",
        "  ⟨devices, ifaces, routes, links, switches, responseSourceGuards⟩",
        "",
        "lemma response_default_checks : ∀ guard ∈ responseSourceGuards,",
        "    (deviceAt devices guard.1).outputFallback = .deny := by decide",
        "",
        "/-- The copied-byte guarantee covers the explicit pre-encryption processing",
        "points, including pre-FORWARD errors and local INPUT handling. Prefix-copy",
        "provenance and kernel hook correspondence are the stated implementation contract. -/",
        "theorem gateway_response_executions_keep_stack",
        "    {before after : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}",
        "    (run : (KernelResponses.lts (GuardedResponseNetwork.network responseData)",
        "      (GuardedResponseNetwork.responseConfig responseData)).MTr",
        "      (.network before) actions (.network after))",
        "    (initial : GuardedResponseNetwork.Safe responseData before) :",
        "    StackInvariant config expectedEncapStack after :=",
        "  GuardedResponseNetwork.all_guarded_response_executions_preserve_stack responseData",
        "    local_stack_conditions all_source_output_reply_pairs_checked all_input_interfaces_covered",
        "    response_default_checks run initial",
        ""
    ]
    for index in range(count):
        lines += [
            "lemma guardedWitnessStep" + str(index) + " :",
            "    (GuardedResponseNetwork.network responseData).Tr witnessState" + str(index) +
            " ." + trace["steps"][index]["action"] + " witnessState" + str(index + 1) + " := by",
            "  exact ⟨witnessStep" + str(index) + ", by decide⟩", ""
        ]
    proof = "Cslib.LTS.MTr.refl"
    for index in reversed(range(count)):
        proof = "Cslib.LTS.MTr.stepL guardedWitnessStep" + str(index) + " (" + proof + ")"
    lines += [
        "theorem positive_delivery_with_early_source_guards :",
        "    (GuardedResponseNetwork.network responseData).MTr witnessState0 witnessActions witnessState" +
        str(count) + " := by",
        "  exact " + proof,
        "",
        "lemma initial_guarded_state_is_safe : GuardedResponseNetwork.Safe responseData witnessState0 := by",
        "  exact ⟨witness_initial_stack, trivial, by decide⟩",
        "",
        "end TDN.Imported." + args.namespace, ""
    ]
    Path(args.output).write_text("\n".join(lines))


if __name__ == "__main__":
    main()
