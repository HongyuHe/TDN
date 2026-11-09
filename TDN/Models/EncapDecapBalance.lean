import TDN.Models.DataPlaneForwarding
import TDN.Models.TraceCreditDebitBalance

namespace TDN.DataPlaneForwarding

def encryptionCredit (action : Action) : Nat := if action = .encrypt then 1 else 0
def decryptionDebit (action : Action) : Nat := if action = .decrypt then 1 else 0

lemma step_envelope_balance {c : DataPlaneModel} {before after : State} {action : Action}
    (step : Step c before action after) :
    after.frame.encapLayers.length + decryptionDebit action =
      before.frame.encapLayers.length + encryptionCredit action := by
  cases step <;> simp_all [encryptionCredit, decryptionDebit, encrypt]

theorem forwarding_envelope_balance (c : DataPlaneModel) {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after) :
    after.frame.encapLayers.length + (actions.map decryptionDebit).sum =
      before.frame.encapLayers.length + (actions.map encryptionCredit).sum :=
  TraceAccounting.trace_balance (lts c) (fun s => s.frame.encapLayers.length)
    encryptionCredit decryptionDebit (fun _ _ _ step => step_envelope_balance step) run

theorem stack_growth_requires_encryptions (c : DataPlaneModel)
    {before after : State} {actions : List Action} (run : (lts c).MTr before actions after) :
    after.frame.encapLayers.length - before.frame.encapLayers.length ≤
      (actions.map encryptionCredit).sum :=
  TraceAccounting.increase_requires_credit (lts c) (fun s => s.frame.encapLayers.length)
    encryptionCredit decryptionDebit (fun _ _ _ step => step_envelope_balance step) run

theorem stack_removal_requires_decryptions (c : DataPlaneModel)
    {before after : State} {actions : List Action} (run : (lts c).MTr before actions after) :
    before.frame.encapLayers.length - after.frame.encapLayers.length ≤
      (actions.map decryptionDebit).sum := by
  have balance := forwarding_envelope_balance c run
  omega

end TDN.DataPlaneForwarding
