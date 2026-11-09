"""Apply generic kernel-response OUTPUT guards to raw-bound native gateway devices."""
import json
import os
from pathlib import Path
from import_snapshot import lean_list

run = Path(os.environ["TDN_OUTPUT_DIR"])
content = ["import TDN.Requirements.MscKernelReplyIsolation",
           "import TDN.Deployments.ProfileShared_DataPlane", "import TDN.Deployments.ProfileBaseline_DataPlane", ""]
bindings = []
for label, namespace in [("shared", "ProfileShared_DataPlane"), ("baseline", "ProfileBaseline_DataPlane")]:
    report = json.loads((run / "experiments" / (label + "-execution-import.json")).read_text())
    snapshot = json.loads((Path(report["snapshot"]) / "snapshot.json").read_text())
    gateways = [device["id"] for device in snapshot["devices"] if device["role"] in ["inner", "outer"]]
    numbers = sorted(report["device_ids"][device] for device in gateways)
    bindings.append({"snapshot": report["snapshot"], "namespace": namespace,
                     "gateway_ids": gateways, "device_numbers": numbers})
    content += ["namespace TDN.Deployments." + namespace,
                "open DataPlaneForwarding", "set_option maxRecDepth 1000000", "set_option maxHeartbeats 0",
                "def responseGateways : List Nat := " + lean_list([str(n) for n in numbers]),
                "lemma table_driven_gateway_response_guards : ∀ device ∈ responseGateways,",
                "    (deviceAt devices device).outputFallback = .deny ∧",
                "    ∀ rule ∈ (deviceAt devices device).outputRules, rule.verdict = .allow →",
                "      KernelResponses.SafeResponseRule rule := by",
                "  unfold responseGateways devices; decide",
                "lemma gateway_response_guards : Requirements.GatewayResponseGuards config responseGateways := by",
                "  intro iface member",
                "  exact table_driven_gateway_response_guards (config.owner iface) member",
                "theorem packet_stack_survives_gateway_echo_and_error_generation",
                "    {start finish : DataPlaneForwarding.State} {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}",
                "    (run : (KernelResponses.lts (lts config)",
                "      (Requirements.nativeKernelResponses config responseGateways)).MTr",
                "      (.network start) actions (.network finish))",
                "    (initial : EncapStackConsistent config expectedEncapStack start) : EncapStackConsistent config expectedEncapStack finish :=",
                "  Requirements.device_packet_stack_with_kernel_response_guards config expectedEncapStack responseGateways",
                "    local_stack_conditions gateway_response_guards run initial",
                "end TDN.Deployments." + namespace, ""]
Path("TDN/Deployments/SnapshotDeviceResponseGuards.lean").write_text("\n".join(content))
(run / "native-response-guard-bindings.json").write_text(json.dumps(bindings, indent=2) + "\n")
