import TDN.Requirements.StandardDataPlaneBridge

namespace TDN.Compliance

lemma device_trace_has_model_trace {S A : Type} (model : ForwardingModel S A)
    (coverage : model.DeviceStepCoverage) {before : S}
    {deviceStart deviceFinish : MultiProtocolForwarding.TunnelForwardingState}
    {operations : List MultiProtocolForwarding.TunnelForwardingAction}
    (run : (⟨model.deviceDataPlane.AcceptedStep⟩ : Cslib.LTS _ _).MTr deviceStart operations deviceFinish)
    (same : model.deviceDataPlane.state before = deviceStart) :
    ∃ actions after, model.ForwardsAlongTrace before actions after ∧
      model.deviceDataPlane.state after = deviceFinish := by
  induction run generalizing before with
  | refl => exact ⟨[], before, .refl, same⟩
  | stepL step rest induction =>
    obtain ⟨action, middle, transition, _, projection⟩ := coverage before _ _ (same ▸ step)
    obtain ⟨actions, after, trace, final⟩ := induction projection
    exact ⟨action :: actions, after, .stepL transition trace, final⟩

end TDN.Compliance
