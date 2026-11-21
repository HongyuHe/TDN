import TDN.Requirements.StandardEthernetWireBridge

namespace TDN.Compliance
open MultiProtocolForwarding

theorem ForwardingModel.lift_accepted_native_run {S A : Type} (model : ForwardingModel S A)
    (covers : model.DeviceStepCoverage) {first last : MultiProtocolForwarding.TunnelForwardingState}
    {operations : List MultiProtocolForwarding.TunnelForwardingAction}
    (run : (Cslib.LTS.mk model.deviceDataPlane.AcceptedStep).MTr first operations last)
    (start : S) (same : model.deviceDataPlane.state start = first) :
    ∃ actions finish, model.ForwardsAlongTrace start actions finish ∧ model.deviceDataPlane.state finish = last := by
  induction run generalizing start with
  | refl => exact ⟨[], start, Cslib.LTS.MTr.refl, same⟩
  | @stepL first operation next operations last step rest ih =>
    obtain ⟨action, after, tr, _, native⟩ := covers start operation next (same.symm ▸ step)
    obtain ⟨actions, finish, tail, final⟩ := ih after native
    exact ⟨action :: actions, finish, Cslib.LTS.MTr.stepL tr tail, final⟩

end TDN.Compliance
