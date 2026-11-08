import TDN.Targets.ResponseIsolation
import TDN.Evidence.FreshSharedIsolation
import TDN.Evidence.FreshBaselineIsolation
import TDN.Evidence.FreshNativeResponseGuards

namespace TDN.Imported.FreshSharedIsolation
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma tagged_gateway_response_guards :
    Targets.GatewayResponseGuards config TDN.Imported.FreshSharedExecution.responseGateways := by
  have checks : ∀ device ∈ TDN.Imported.FreshSharedExecution.responseGateways,
      (deviceAt taggedDevices device).outputFallback = .deny ∧
      ∀ rule ∈ (deviceAt taggedDevices device).outputRules, rule.verdict = .allow →
        KernelResponses.SafeResponseRule rule := by
    simp only [TDN.Imported.FreshSharedExecution.responseGateways, taggedDevices,
      TDN.Imported.FreshSharedExecution.devices, ownerTag, ownerDomain]
    decide
  intro iface member
  exact checks (config.owner iface) member

theorem gateway_response_delivery_preserves_full_label
    {start finish : Execution.State}
    {actions : List (KernelResponses.Action Execution.Action)}
    {source recipient : Nat}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (sourceLevel : config.recipientDomain start.iface = some source)
    (run : (KernelResponses.lts (lts config)
      (Targets.nativeKernelResponses config TDN.Imported.FreshSharedExecution.responseGateways)).MTr
      (.network start) actions (.network finish))
    (delivered : finish.datapathStage = .delivered)
    (recipientLevel : config.recipientDomain finish.iface = some recipient) :
    fullLevel source = fullLevel recipient := by
  exact congrArg fullLevel (Targets.same_domain_delivery_with_strict_gateway_responses
    config redSources TDN.Imported.FreshSharedExecution.responseGateways snapshot_RG008_IPv4_ESP_delivery
    tagged_gateway_response_guards origin sourceLevel run delivered recipientLevel)

end TDN.Imported.FreshSharedIsolation

namespace TDN.Imported.FreshBaselineIsolation
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma tagged_gateway_response_guards :
    Targets.GatewayResponseGuards config TDN.Imported.FreshBaselineExecution.responseGateways := by
  have checks : ∀ device ∈ TDN.Imported.FreshBaselineExecution.responseGateways,
      (deviceAt taggedDevices device).outputFallback = .deny ∧
      ∀ rule ∈ (deviceAt taggedDevices device).outputRules, rule.verdict = .allow →
        KernelResponses.SafeResponseRule rule := by
    simp only [TDN.Imported.FreshBaselineExecution.responseGateways, taggedDevices,
      TDN.Imported.FreshBaselineExecution.devices, ownerTag, ownerDomain]
    decide
  intro iface member
  exact checks (config.owner iface) member

theorem gateway_response_delivery_preserves_full_label
    {start finish : Execution.State}
    {actions : List (KernelResponses.Action Execution.Action)}
    {source recipient : Nat}
    (origin : Targets.RedPayloadOrigin config redSources start)
    (sourceLevel : config.recipientDomain start.iface = some source)
    (run : (KernelResponses.lts (lts config)
      (Targets.nativeKernelResponses config TDN.Imported.FreshBaselineExecution.responseGateways)).MTr
      (.network start) actions (.network finish))
    (delivered : finish.datapathStage = .delivered)
    (recipientLevel : config.recipientDomain finish.iface = some recipient) :
    fullLevel source = fullLevel recipient := by
  exact congrArg fullLevel (Targets.same_domain_delivery_with_strict_gateway_responses
    config redSources TDN.Imported.FreshBaselineExecution.responseGateways snapshot_RG008_IPv4_ESP_delivery
    tagged_gateway_response_guards origin sourceLevel run delivered recipientLevel)

end TDN.Imported.FreshBaselineIsolation

