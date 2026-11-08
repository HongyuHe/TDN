"""Apply generic kernel-response OUTPUT guards to raw-bound native gateway devices."""
import json
import os
from pathlib import Path
from import_snapshot import lean_list

run = Path(os.environ["TDN_OUTPUT_DIR"])
content = ["import TDN.Targets.KernelResponses",
           "import TDN.Evidence.FreshSharedExecution", "import TDN.Evidence.FreshBaselineExecution", ""]
bindings = []
for label, namespace in [("shared", "FreshSharedExecution"), ("baseline", "FreshBaselineExecution")]:
    report = json.loads((run / "experiments" / (label + "-execution-import.json")).read_text())
    snapshot = json.loads((Path(report["snapshot"]) / "snapshot.json").read_text())
    gateways = [device["id"] for device in snapshot["devices"] if device["role"] in ["inner", "outer"]]
    numbers = sorted(report["device_ids"][device] for device in gateways)
    bindings.append({"snapshot": report["snapshot"], "namespace": namespace,
                     "gateway_ids": gateways, "device_numbers": numbers})
    content += ["namespace TDN.Imported." + namespace,
                "open Execution", "set_option maxRecDepth 1000000", "set_option maxHeartbeats 0",
                "def responseGateways : List Nat := " + lean_list([str(n) for n in numbers]),
                "lemma finite_gateway_response_guards : ∀ device ∈ responseGateways,",
                "    (deviceAt devices device).outputFallback = .deny ∧",
                "    ∀ rule ∈ (deviceAt devices device).outputRules, rule.verdict = .allow →",
                "      KernelResponses.SafeResponseRule rule := by",
                "  unfold responseGateways devices; decide",
                "lemma gateway_response_guards : Targets.GatewayResponseGuards config responseGateways := by",
                "  intro iface member",
                "  exact finite_gateway_response_guards (config.owner iface) member",
                "theorem packet_stack_survives_gateway_echo_and_error_generation",
                "    {start finish : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}",
                "    (run : (KernelResponses.lts (lts config)",
                "      (Targets.nativeKernelResponses config responseGateways)).MTr",
                "      (.network start) actions (.network finish))",
                "    (initial : StackInvariant config expectedEncapStack start) : StackInvariant config expectedEncapStack finish :=",
                "  Targets.native_packet_stack_with_kernel_response_guards config expectedEncapStack responseGateways",
                "    local_stack_conditions gateway_response_guards run initial",
                "end TDN.Imported." + namespace, ""]
Path("TDN/Evidence/FreshNativeResponseGuards.lean").write_text("\n".join(content))
(run / "native-response-guard-bindings.json").write_text(json.dumps(bindings, indent=2) + "\n")
