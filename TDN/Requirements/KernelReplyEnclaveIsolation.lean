import TDN.Models.BlockedRepliesReduceToForwarding
import TDN.Requirements.MscKernelReplyIsolation
import TDN.Requirements.PacketEnclaveIsolation

namespace TDN.Requirements

theorem same_domain_delivery_with_strict_gateway_responses
    (c : DataPlaneForwarding.DataPlaneModel) (sources gateways : List Nat)
    (delivery : plaintext_delivery_preserves_security_enclave c sources)
    (guards : GatewayResponseGuards c gateways)
    {start finish : DataPlaneForwarding.State}
    {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    {sourceDomain destinationDomain : Nat}
    (origin : RedPayloadOrigin c sources start)
    (sourceLevel : c.ifaceSecurityDomain start.iface = some sourceDomain)
    (run : (KernelResponses.lts (DataPlaneForwarding.lts c)
      (nativeKernelResponses c gateways)).MTr (.network start) actions (.network finish))
    (delivered : finish.datapathStage = .delivered)
    (recipientLevel : c.ifaceSecurityDomain finish.iface = some destinationDomain) :
    sourceDomain = destinationDomain := by
  have checked : ∀ source, (nativeKernelResponses c gateways).generates source → ∀ iface,
      (nativeKernelResponses c gateways).outputFallback source iface = .deny ∧
      ∀ rule ∈ (nativeKernelResponses c gateways).outputRules source iface,
        rule.verdict = .allow → KernelResponses.SafeResponseRule rule := by
    intro source enabled iface
    exact guards source.iface enabled
  obtain ⟨labels, underlying⟩ :=
    KernelResponses.strict_response_result_has_network_forwarding
      (DataPlaneForwarding.lts c) (nativeKernelResponses c gateways) checked run
  exact delivery start finish labels sourceDomain destinationDomain
    origin sourceLevel underlying delivered recipientLevel

end TDN.Requirements
