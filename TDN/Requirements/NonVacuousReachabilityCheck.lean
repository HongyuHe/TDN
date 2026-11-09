import TDN.Requirements.StandardEthernetWireBridge

namespace TDN.Compliance
open MultiProtocolForwarding

theorem ForwardingModel.lift_accepted_native_run {S A : Type} (model : ForwardingModel S A)
    (covers : model.DeviceStepCoverage) {first last : MultiProtocolForwarding.State}
    {operations : List MultiProtocolForwarding.Action}
    (run : (Cslib.LTS.mk model.native.AcceptedStep).MTr first operations last)
    (start : S) (same : model.native.state start = first) :
    ∃ actions finish, model.system.MTr start actions finish ∧ model.native.state finish = last := by
  induction run generalizing start with
  | refl => exact ⟨[], start, Cslib.LTS.MTr.refl, same⟩
  | @stepL first operation next operations last step rest ih =>
    obtain ⟨action, after, tr, _, native⟩ := covers start operation next (same.symm ▸ step)
    obtain ⟨actions, finish, tail, final⟩ := ih after native
    exact ⟨action :: actions, finish, Cslib.LTS.MTr.stepL tr tail, final⟩

end TDN.Compliance
