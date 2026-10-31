import TDN.Targets.KernelResponses
import TDN.Evidence.FreshSharedExecution
import TDN.Evidence.FreshBaselineExecution

namespace TDN.Imported.FreshSharedExecution
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
def responseGateways : List Nat := [12, 13, 14, 15, 16, 17, 18, 19, 22, 23]
lemma finite_gateway_response_guards : ∀ device ∈ responseGateways,
    (deviceAt devices device).outputFallback = .deny ∧
    ∀ rule ∈ (deviceAt devices device).outputRules, rule.verdict = .allow →
      KernelResponses.SafeResponseRule rule := by
  unfold responseGateways devices; decide
lemma gateway_response_guards : Targets.GatewayResponseGuards config responseGateways := by
  intro port member
  exact finite_gateway_response_guards (config.owner port) member
theorem packet_stack_survives_gateway_echo_and_error_generation
    {start finish : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (lts config)
      (Targets.nativeKernelResponses config responseGateways)).MTr
      (.network start) actions (.network finish))
    (initial : StackInvariant config layout start) : StackInvariant config layout finish :=
  Targets.native_packet_stack_with_kernel_response_guards config layout responseGateways
    local_stack_conditions gateway_response_guards run initial
end TDN.Imported.FreshSharedExecution

namespace TDN.Imported.FreshBaselineExecution
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
def responseGateways : List Nat := [8, 9, 10, 11, 16, 17, 18, 19]
lemma finite_gateway_response_guards : ∀ device ∈ responseGateways,
    (deviceAt devices device).outputFallback = .deny ∧
    ∀ rule ∈ (deviceAt devices device).outputRules, rule.verdict = .allow →
      KernelResponses.SafeResponseRule rule := by
  unfold responseGateways devices; decide
lemma gateway_response_guards : Targets.GatewayResponseGuards config responseGateways := by
  intro port member
  exact finite_gateway_response_guards (config.owner port) member
theorem packet_stack_survives_gateway_echo_and_error_generation
    {start finish : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (lts config)
      (Targets.nativeKernelResponses config responseGateways)).MTr
      (.network start) actions (.network finish))
    (initial : StackInvariant config layout start) : StackInvariant config layout finish :=
  Targets.native_packet_stack_with_kernel_response_guards config layout responseGateways
    local_stack_conditions gateway_response_guards run initial
end TDN.Imported.FreshBaselineExecution
