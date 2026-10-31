import TDN.Semantics.KernelResponses
import TDN.Targets.PacketExecution

namespace TDN.Targets

def nativeKernelResponses (c : Execution.Config) (gatewayDevices : List Nat) :
    KernelResponses.Config Execution.State where
  generates state := c.owner state.port ∈ gatewayDevices
  selectedRoute state header port := ∃ route,
    Execution.SelectedRoute c.routes route header ∧ route.ingress = state.port ∧ route.egress = port
  outputRules state _ := c.outputRules state.port
  outputFallback state _ := c.outputFallback state.port
  interfaceName := c.interfaceName
  emit state header port :=
    { port := port, phase := .ready, frame := { state.frame with packet := header }, authenticated := [] }

def GatewayResponseGuards (c : Execution.Config) (gatewayDevices : List Nat) : Prop :=
  ∀ port, c.owner port ∈ gatewayDevices →
    c.outputFallback port = .deny ∧
    ∀ rule ∈ c.outputRules port, rule.verdict = .allow → KernelResponses.SafeResponseRule rule

theorem native_packet_stack_with_kernel_response_guards
    (c : Execution.Config) (layout : Nat → List Nat) (gatewayDevices : List Nat)
    (conditions : Execution.LocalStackConditions c layout)
    (guards : GatewayResponseGuards c gatewayDevices)
    {before after : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (Execution.lts c) (nativeKernelResponses c gatewayDevices)).MTr
      (.network before) actions (.network after))
    (initial : Execution.StackInvariant c layout before) :
    Execution.StackInvariant c layout after := by
  apply KernelResponses.network_observations_remain_safe_with_kernel_responses
    (Execution.lts c) (nativeKernelResponses c gatewayDevices)
    (Execution.StackInvariant c layout)
    (fun _ _ _ step valid => Execution.step_preserves_stack_invariant conditions step valid)
    ?_ run initial
  intro source enabled port
  exact guards source.port enabled

end TDN.Targets
