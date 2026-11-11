import TDN.Deployments.NestedProtection_MixedTraceData

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def FrameAdmissionCheck (state : MultiProtocolForwarding.State) (iface : Nat) (outbound : Bool) : Prop :=
  match state.frame.body with
  | .macsec _ _ => ∃ encoded ∈ records.macFrames,
      configuration.linkEncoding iface state.frame = some encoded.2 ∧
      encoded.2.DescribesBody state.frame.body ∧
      LinkAdmission.Admitted configuration.linkPolicies iface outbound
        (encoded.2.Packet (if outbound then "" else configuration.ip.interfaceName iface)
          (if outbound then configuration.ip.interfaceName iface else ""))
  | _ => False

instance (state : MultiProtocolForwarding.State) (iface : Nat) (outbound : Bool) :
    Decidable (FrameAdmissionCheck state iface outbound) := by
  unfold FrameAdmissionCheck
  cases state.frame.body <;> dsimp only <;> infer_instance

lemma frame_admission_from_check (state : MultiProtocolForwarding.State) (iface : Nat) (outbound : Bool)
    (checked : FrameAdmissionCheck state iface outbound) :
    configuration.LinkAdmitted iface outbound state.frame := by
  cases shape : state.frame.body <;> simp only [FrameAdmissionCheck, shape] at checked
  next association contents =>
    obtain ⟨encoded, member, encoding, describes, admitted⟩ := checked
    refine ⟨encoded.2, encoding, ?_, admitted⟩
    simp only [LinkAdmission.Frame.Describes, Frame.visibleHeader, shape, Body.visibleHeader]
    exact ⟨describes, by simp⟩

end TDN.Deployments.NestedProtection_Mixed
