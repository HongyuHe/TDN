import TDN.Models.DataPlaneForwarding
import TDN.Models.TracePushPopBalance

namespace TDN.DataPlaneForwarding

def encapsulationCount (action : ForwardingAction) : Nat := if action = .encrypt then 1 else 0
def decapsulationCount (action : ForwardingAction) : Nat := if action = .decrypt then 1 else 0

lemma step_envelope_balance {c : DataPlaneModel} {before after : ForwardingState} {action : ForwardingAction}
    (step : ForwardingStep c before action after) :
    after.frame.encapLayers.length + decapsulationCount action =
      before.frame.encapLayers.length + encapsulationCount action := by
  cases step <;> simp_all [encapsulationCount, decapsulationCount, encrypt]

theorem forwarding_envelope_balance (c : DataPlaneModel) {before after : ForwardingState} {actions : List ForwardingAction}
    (run : (lts c).MTr before actions after) :
    after.frame.encapLayers.length + (actions.map decapsulationCount).sum =
      before.frame.encapLayers.length + (actions.map encapsulationCount).sum :=
  TracePushPopBalance.trace_balance (lts c) (fun s => s.frame.encapLayers.length)
    encapsulationCount decapsulationCount (fun _ _ _ step => step_envelope_balance step) run

theorem stack_growth_requires_encryptions (c : DataPlaneModel)
    {before after : ForwardingState} {actions : List ForwardingAction} (run : (lts c).MTr before actions after) :
    after.frame.encapLayers.length - before.frame.encapLayers.length ≤
      (actions.map encapsulationCount).sum :=
  TracePushPopBalance.increase_requires_pushes (lts c) (fun s => s.frame.encapLayers.length)
    encapsulationCount decapsulationCount (fun _ _ _ step => step_envelope_balance step) run

theorem stack_removal_requires_decryptions (c : DataPlaneModel)
    {before after : ForwardingState} {actions : List ForwardingAction} (run : (lts c).MTr before actions after) :
    before.frame.encapLayers.length - after.frame.encapLayers.length ≤
      (actions.map decapsulationCount).sum := by
  have balance := forwarding_envelope_balance c run
  omega

end TDN.DataPlaneForwarding
