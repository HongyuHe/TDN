import TDN.Requirements.KernelReplyEnclaveIsolation
import TDN.Deployments.ProfileShared_EnclaveIsolation
import TDN.Deployments.ProfileBaseline_EnclaveIsolation
import TDN.Deployments.SnapshotDeviceResponseGuards

namespace TDN.Deployments.ProfileShared_EnclaveIsolation
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma tagged_gateway_response_guards :
    Requirements.GatewayResponseGuards config TDN.Deployments.ProfileShared_DataPlane.responseGateways := by
  have checks : ∀ device ∈ TDN.Deployments.ProfileShared_DataPlane.responseGateways,
      (deviceAt taggedDevices device).outputFallback = .deny ∧
      ∀ rule ∈ (deviceAt taggedDevices device).outputRules, rule.verdict = .allow →
        KernelResponses.SafeResponseRule rule := by
    simp only [TDN.Deployments.ProfileShared_DataPlane.responseGateways, taggedDevices,
      TDN.Deployments.ProfileShared_DataPlane.devices, ownerTag, ownerDomain]
    native_decide
  intro iface member
  exact checks (config.owner iface) member

theorem gateway_response_delivery_preserves_full_label
    {start finish : DataPlaneForwarding.State}
    {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    {source recipient : Nat}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (sourceLevel : config.ifaceSecurityDomain start.iface = some source)
    (run : (KernelResponses.lts (lts config)
      (Requirements.nativeKernelResponses config TDN.Deployments.ProfileShared_DataPlane.responseGateways)).MTr
      (.network start) actions (.network finish))
    (delivered : finish.datapathStage = .delivered)
    (recipientLevel : config.ifaceSecurityDomain finish.iface = some recipient) :
    fullLevel source = fullLevel recipient := by
  exact congrArg fullLevel (Requirements.same_domain_delivery_with_strict_gateway_responses
    config redSources TDN.Deployments.ProfileShared_DataPlane.responseGateways snapshot_RG008_IPv4_ESP_delivery
    tagged_gateway_response_guards origin sourceLevel run delivered recipientLevel)

end TDN.Deployments.ProfileShared_EnclaveIsolation

namespace TDN.Deployments.ProfileBaseline_EnclaveIsolation
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma tagged_gateway_response_guards :
    Requirements.GatewayResponseGuards config TDN.Deployments.ProfileBaseline_DataPlane.responseGateways := by
  have checks : ∀ device ∈ TDN.Deployments.ProfileBaseline_DataPlane.responseGateways,
      (deviceAt taggedDevices device).outputFallback = .deny ∧
      ∀ rule ∈ (deviceAt taggedDevices device).outputRules, rule.verdict = .allow →
        KernelResponses.SafeResponseRule rule := by
    simp only [TDN.Deployments.ProfileBaseline_DataPlane.responseGateways, taggedDevices,
      TDN.Deployments.ProfileBaseline_DataPlane.devices, ownerTag, ownerDomain]
    native_decide
  intro iface member
  exact checks (config.owner iface) member

theorem gateway_response_delivery_preserves_full_label
    {start finish : DataPlaneForwarding.State}
    {actions : List (KernelResponses.Action DataPlaneForwarding.Action)}
    {source recipient : Nat}
    (origin : Requirements.RedPayloadOrigin config redSources start)
    (sourceLevel : config.ifaceSecurityDomain start.iface = some source)
    (run : (KernelResponses.lts (lts config)
      (Requirements.nativeKernelResponses config TDN.Deployments.ProfileBaseline_DataPlane.responseGateways)).MTr
      (.network start) actions (.network finish))
    (delivered : finish.datapathStage = .delivered)
    (recipientLevel : config.ifaceSecurityDomain finish.iface = some recipient) :
    fullLevel source = fullLevel recipient := by
  exact congrArg fullLevel (Requirements.same_domain_delivery_with_strict_gateway_responses
    config redSources TDN.Deployments.ProfileBaseline_DataPlane.responseGateways snapshot_RG008_IPv4_ESP_delivery
    tagged_gateway_response_guards origin sourceLevel run delivered recipientLevel)

end TDN.Deployments.ProfileBaseline_EnclaveIsolation
