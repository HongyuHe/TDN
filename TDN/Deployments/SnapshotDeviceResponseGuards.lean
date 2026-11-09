import TDN.Import.SnapshotLoader
import TDN.Requirements.MscKernelReplyIsolation
import TDN.Deployments.ProfileShared_DataPlane
import TDN.Deployments.ProfileBaseline_DataPlane

namespace TDN.Deployments.ProfileShared_DataPlane
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
load_network_records responseGateways : List Nat from "../../data/evidence/SnapshotDeviceResponseGuards.json" ["TDN.Deployments.ProfileShared_DataPlane.responseGateways"]

lemma table_driven_gateway_response_guards : ∀ device ∈ responseGateways,
    (deviceAt devices device).outputFallback = .deny ∧
    ∀ rule ∈ (deviceAt devices device).outputRules, rule.verdict = .allow →
      KernelResponses.SafeResponseRule rule := by
  unfold responseGateways devices; decide
lemma gateway_response_guards : Requirements.GatewayResponseGuards config responseGateways := by
  intro iface member
  exact table_driven_gateway_response_guards (config.owner iface) member
theorem packet_stack_survives_gateway_echo_and_error_generation
    {start finish : DataPlaneForwarding.State} {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    (run : (KernelResponses.lts (lts config)
      (Requirements.nativeKernelResponses config responseGateways)).MTr
      (.network start) actions (.network finish))
    (initial : EncapStackConsistent config expectedEncapStack start) : EncapStackConsistent config expectedEncapStack finish :=
  Requirements.device_packet_stack_with_kernel_response_guards config expectedEncapStack responseGateways
    local_stack_conditions gateway_response_guards run initial
end TDN.Deployments.ProfileShared_DataPlane

namespace TDN.Deployments.ProfileBaseline_DataPlane
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
load_network_records responseGateways : List Nat from "../../data/evidence/SnapshotDeviceResponseGuards.json" ["TDN.Deployments.ProfileBaseline_DataPlane.responseGateways"]

lemma table_driven_gateway_response_guards : ∀ device ∈ responseGateways,
    (deviceAt devices device).outputFallback = .deny ∧
    ∀ rule ∈ (deviceAt devices device).outputRules, rule.verdict = .allow →
      KernelResponses.SafeResponseRule rule := by
  unfold responseGateways devices; decide
lemma gateway_response_guards : Requirements.GatewayResponseGuards config responseGateways := by
  intro iface member
  exact table_driven_gateway_response_guards (config.owner iface) member
theorem packet_stack_survives_gateway_echo_and_error_generation
    {start finish : DataPlaneForwarding.State} {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    (run : (KernelResponses.lts (lts config)
      (Requirements.nativeKernelResponses config responseGateways)).MTr
      (.network start) actions (.network finish))
    (initial : EncapStackConsistent config expectedEncapStack start) : EncapStackConsistent config expectedEncapStack finish :=
  Requirements.device_packet_stack_with_kernel_response_guards config expectedEncapStack responseGateways
    local_stack_conditions gateway_response_guards run initial
end TDN.Deployments.ProfileBaseline_DataPlane
