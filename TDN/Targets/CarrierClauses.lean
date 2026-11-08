import TDN.Semantics.MultiProtocolExecution

namespace TDN.Targets
open MultiProtocolExecution LayeredFrame

theorem carrier_step_wraps_the_exact_input_body (config : Config)
    {before after : State} (step : Step config before .encapsulate after) :
    ∃ carrier, after.frame.body = .carrier carrier before.frame.body := by
  cases step with
  | encapsulate iface configured datapathStage virtualIface => exact ⟨iface.transmit, by simp⟩

theorem carrier_step_preserves_existing_protection (config : Config)
    {before after : State} (step : Step config before .encapsulate after) :
    after.frame.body.protectionLayers = before.frame.body.protectionLayers ∧
      after.frame.body.originalEthernet = before.frame.body.originalEthernet := by
  obtain ⟨carrier, body⟩ := carrier_step_wraps_the_exact_input_body config step
  rw [body]
  exact ⟨rfl, rfl⟩

end TDN.Targets
