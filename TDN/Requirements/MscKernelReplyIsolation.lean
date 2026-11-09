import TDN.Models.KernelGeneratedReplies
import TDN.Requirements.DoubleEncryptionOnBlackLinks

namespace TDN.Requirements

def nativeKernelResponses (c : DataPlaneForwarding.DataPlaneModel) (gatewayDevices : List Nat) :
    KernelResponses.Config DataPlaneForwarding.State where
  generates state := c.owner state.iface ∈ gatewayDevices
  selectedRoute state header iface := ∃ route,
    DataPlaneForwarding.SelectedFibRoute c.routes route header ∧ route.ingress = state.iface ∧ route.egress = iface
  outputRules state _ := c.outputRules state.iface
  outputFallback state _ := c.outputFallback state.iface
  interfaceName := c.interfaceName
  emit state header iface :=
    { iface := iface, datapathStage := .egressReady, frame := { state.frame with packet := header }, authenticated := [] }

def GatewayResponseGuards (c : DataPlaneForwarding.DataPlaneModel) (gatewayDevices : List Nat) : Prop :=
  ∀ iface, c.owner iface ∈ gatewayDevices →
    c.outputFallback iface = .deny ∧
    ∀ rule ∈ c.outputRules iface, rule.verdict = .allow → KernelResponses.SafeResponseRule rule

theorem device_packet_stack_with_kernel_response_guards
    (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat) (gatewayDevices : List Nat)
    (conditions : DataPlaneForwarding.PerHopEncapConditions c expectedEncapStack)
    (guards : GatewayResponseGuards c gatewayDevices)
    {before after : DataPlaneForwarding.State} {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    (run : (KernelResponses.lts (DataPlaneForwarding.lts c) (nativeKernelResponses c gatewayDevices)).MTr
      (.network before) actions (.network after))
    (initial : DataPlaneForwarding.EncapStackConsistent c expectedEncapStack before) :
    DataPlaneForwarding.EncapStackConsistent c expectedEncapStack after := by
  apply KernelResponses.network_observations_remain_safe_with_kernel_responses
    (DataPlaneForwarding.lts c) (nativeKernelResponses c gatewayDevices)
    (DataPlaneForwarding.EncapStackConsistent c expectedEncapStack)
    (fun _ _ _ step valid => DataPlaneForwarding.hop_preserves_encap_stack conditions step valid)
    ?_ run initial
  intro source enabled iface
  exact guards source.iface enabled

end TDN.Requirements
