import TDN.Semantics.Execution
import TDN.Semantics.TraceAccounting

namespace TDN.Execution

def encryptionCredit (action : Action) : Nat := if action = .encrypt then 1 else 0
def decryptionDebit (action : Action) : Nat := if action = .decrypt then 1 else 0

lemma step_envelope_balance {c : Config} {before after : State} {action : Action}
    (step : Step c before action after) :
    after.frame.envelopes.length + decryptionDebit action =
      before.frame.envelopes.length + encryptionCredit action := by
  cases step <;> simp_all [encryptionCredit, decryptionDebit, encrypt]

theorem execution_envelope_balance (c : Config) {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after) :
    after.frame.envelopes.length + (actions.map decryptionDebit).sum =
      before.frame.envelopes.length + (actions.map encryptionCredit).sum :=
  TraceAccounting.trace_balance (lts c) (fun s => s.frame.envelopes.length)
    encryptionCredit decryptionDebit (fun _ _ _ step => step_envelope_balance step) run

theorem stack_growth_requires_encryptions (c : Config)
    {before after : State} {actions : List Action} (run : (lts c).MTr before actions after) :
    after.frame.envelopes.length - before.frame.envelopes.length ≤
      (actions.map encryptionCredit).sum :=
  TraceAccounting.increase_requires_credit (lts c) (fun s => s.frame.envelopes.length)
    encryptionCredit decryptionDebit (fun _ _ _ step => step_envelope_balance step) run

theorem stack_removal_requires_decryptions (c : Config)
    {before after : State} {actions : List Action} (run : (lts c).MTr before actions after) :
    before.frame.envelopes.length - after.frame.envelopes.length ≤
      (actions.map decryptionDebit).sum := by
  have balance := execution_envelope_balance c run
  omega

end TDN.Execution
