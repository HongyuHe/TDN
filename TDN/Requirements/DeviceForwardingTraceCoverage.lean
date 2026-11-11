import TDN.Requirements.StandardDataPlaneBridge

namespace TDN.Compliance

lemma device_trace_has_model_trace {S A : Type} (model : ForwardingModel S A)
    (coverage : model.DeviceStepCoverage) {before : S}
    {deviceStart deviceFinish : MultiProtocolForwarding.State}
    {operations : List MultiProtocolForwarding.Action}
    (run : (⟨model.native.AcceptedStep⟩ : Cslib.LTS _ _).MTr deviceStart operations deviceFinish)
    (same : model.native.state before = deviceStart) :
    ∃ actions after, model.system.MTr before actions after ∧
      model.native.state after = deviceFinish := by
  induction run generalizing before with
  | refl => exact ⟨[], before, .refl, same⟩
  | stepL step rest induction =>
    obtain ⟨action, middle, transition, _, projection⟩ := coverage before _ _ (same ▸ step)
    obtain ⟨actions, after, trace, final⟩ := induction projection
    exact ⟨action :: actions, after, .stepL transition trace, final⟩

end TDN.Compliance
