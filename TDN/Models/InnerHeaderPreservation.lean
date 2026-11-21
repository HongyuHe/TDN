import TDN.Models.MultiProtocolEncryptionEvents

namespace TDN.MultiProtocolForwarding
open LayeredFrame

lemma unwrap_preserves_original_header
    (localAddress remote sourcePort destinationPort localSession : Nat)
    {protocol networkProtocol : String} (before after : Body)
    (unwrapped : unwrapCarrier localAddress remote sourcePort destinationPort localSession
      before protocol networkProtocol = some after) :
    after.originalHeader = before.originalHeader := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    next matched => cases unwrapped; rfl
    next missed => cases unwrapped

lemma step_preserves_original_header {c : TunnelForwardingModel} {before after : TunnelForwardingState} {action : TunnelForwardingAction}
    (step : TunnelForwardingStep c before action after) :
    after.frame.body.originalHeader = before.frame.body.originalHeader := by
  cases step <;> simp only [TunnelForwardingModel.forwarded_frame_body, TunnelForwardingModel.ipsec_frame_body,
    TunnelForwardingModel.macsec_frame_body, TunnelForwardingModel.macsec_pdu_frame_body, TunnelForwardingModel.carrier_frame_body, TunnelForwardingModel.restored_frame_body] <;> try rfl
  all_goals try simp_all only [Body.originalHeader]
  all_goals exact unwrap_preserves_original_header _ _ _ _ _ _ _ ‹_›

theorem all_traces_preserve_original_header (c : TunnelForwardingModel)
    {before after : TunnelForwardingState} {actions : List TunnelForwardingAction} (run : (lts c).MTr before actions after) :
    after.frame.body.originalHeader = before.frame.body.originalHeader := by
  have preserved : (lts c).TrInv
      (fun state => state.frame.body.originalHeader = before.frame.body.originalHeader) := by
    intro first action last step valid
    exact (step_preserves_original_header step).trans valid
  exact Cslib.LTS.mtrInv_of_trInv preserved before actions after run rfl

end TDN.MultiProtocolForwarding
