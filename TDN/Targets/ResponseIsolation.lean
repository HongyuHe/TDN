import TDN.Semantics.StrictResponseProjection
import TDN.Targets.KernelResponses
import TDN.Targets.DeliveryIsolation

namespace TDN.Targets

theorem same_domain_delivery_with_strict_gateway_responses
    (c : Execution.Environment) (sources gateways : List Nat)
    (delivery : msc_same_domain_plaintext_delivery c sources)
    (guards : GatewayResponseGuards c gateways)
    {start finish : Execution.State}
    {actions : List (KernelResponses.Action Execution.Action)}
    {sourceDomain recipientDomain : Nat}
    (origin : RedPayloadOrigin c sources start)
    (sourceLevel : c.recipientDomain start.iface = some sourceDomain)
    (run : (KernelResponses.lts (Execution.lts c)
      (nativeKernelResponses c gateways)).MTr (.network start) actions (.network finish))
    (delivered : finish.datapathStage = .delivered)
    (recipientLevel : c.recipientDomain finish.iface = some recipientDomain) :
    sourceDomain = recipientDomain := by
  have checked : ∀ source, (nativeKernelResponses c gateways).generates source → ∀ iface,
      (nativeKernelResponses c gateways).outputFallback source iface = .deny ∧
      ∀ rule ∈ (nativeKernelResponses c gateways).outputRules source iface,
        rule.verdict = .allow → KernelResponses.SafeResponseRule rule := by
    intro source enabled iface
    exact guards source.iface enabled
  obtain ⟨labels, underlying⟩ :=
    KernelResponses.strict_response_result_has_network_execution
      (Execution.lts c) (nativeKernelResponses c gateways) checked run
  exact delivery start finish labels sourceDomain recipientDomain
    origin sourceLevel underlying delivered recipientLevel

end TDN.Targets
