import TDN.Semantics.KernelResponses
import TDN.Targets.PacketExecution

namespace TDN.Targets

def nativeKernelResponses (c : Execution.Environment) (gatewayDevices : List Nat) :
    KernelResponses.Config Execution.State where
  generates state := c.owner state.iface ∈ gatewayDevices
  selectedRoute state header iface := ∃ route,
    Execution.SelectedRoute c.routes route header ∧ route.ingress = state.iface ∧ route.egress = iface
  outputRules state _ := c.outputRules state.iface
  outputFallback state _ := c.outputFallback state.iface
  interfaceName := c.interfaceName
  emit state header iface :=
    { iface := iface, datapathStage := .ready, frame := { state.frame with packet := header }, authenticated := [] }

def GatewayResponseGuards (c : Execution.Environment) (gatewayDevices : List Nat) : Prop :=
  ∀ iface, c.owner iface ∈ gatewayDevices →
    c.outputFallback iface = .deny ∧
    ∀ rule ∈ c.outputRules iface, rule.verdict = .allow → KernelResponses.SafeResponseRule rule

theorem native_packet_stack_with_kernel_response_guards
    (c : Execution.Environment) (expectedEncapStack : Nat → List Nat) (gatewayDevices : List Nat)
    (conditions : Execution.LocalStackConditions c expectedEncapStack)
    (guards : GatewayResponseGuards c gatewayDevices)
    {before after : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (Execution.lts c) (nativeKernelResponses c gatewayDevices)).MTr
      (.network before) actions (.network after))
    (initial : Execution.StackInvariant c expectedEncapStack before) :
    Execution.StackInvariant c expectedEncapStack after := by
  apply KernelResponses.network_observations_remain_safe_with_kernel_responses
    (Execution.lts c) (nativeKernelResponses c gatewayDevices)
    (Execution.StackInvariant c expectedEncapStack)
    (fun _ _ _ step valid => Execution.step_preserves_stack_invariant conditions step valid)
    ?_ run initial
  intro source enabled iface
  exact guards source.iface enabled

end TDN.Targets
