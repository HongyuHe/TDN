import TDN.Models.MultiProtocolForwarding

namespace TDN.Requirements
open MultiProtocolForwarding LayeredFrame

theorem carrier_step_wraps_the_exact_input_body (config : TunnelForwardingModel)
    {before after : TunnelForwardingState} (step : TunnelForwardingStep config before .encapsulate after) :
    ∃ carrier, after.frame.body = .carrier carrier before.frame.body := by
  cases step with
  | encapsulate iface configured datapathStage virtualIface => exact ⟨iface.transmit, by simp⟩

theorem carrier_step_preserves_existing_protection (config : TunnelForwardingModel)
    {before after : TunnelForwardingState} (step : TunnelForwardingStep config before .encapsulate after) :
    after.frame.body.protectionLayers = before.frame.body.protectionLayers ∧
      after.frame.body.originalEthernet = before.frame.body.originalEthernet := by
  obtain ⟨carrier, body⟩ := carrier_step_wraps_the_exact_input_body config step
  rw [body]
  exact ⟨rfl, rfl⟩

end TDN.Requirements
