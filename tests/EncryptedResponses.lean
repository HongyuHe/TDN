import TDN.Semantics.EncryptedResponseGuards
import TDN.Evidence.FreshFamily444V13Witness

namespace EncryptedResponseRegression
open TDN TDN.Execution TDN.EncryptedResponseGuards

def association : Association := ⟨10, 1, 100, 200, 1, 10, 11, 20, 0, none⟩

/-- A broad ICMP allowance cannot establish encrypted-error output denial. -/
example : ¬ FiniteDeny [{
    outbound := [association],
    outputRules := [⟨[.protocol "icmp"], .allow⟩] }] := by
  unfold FiniteDeny
  decide

/-- A reply destination interval disjoint from the local wire source is sufficient. -/
example : FiniteDeny [{
    outbound := [association],
    outputRules := [⟨[.protocol "icmp", .destinationRange 200 200], .allow⟩] }] := by
  unfold FiniteDeny
  decide

/-- A permissive fallback is detected even if no allow rule exists. -/
example : ¬ FiniteDeny [{ outbound := [association], outputFallback := .allow }] := by
  unfold FiniteDeny
  decide

/-- The actual positive path reaches the new post-encryption generation class. -/
example : LocallyEncrypted Imported.Family444V13.config Imported.Family444V13.witnessState8 :=
  encryption_step_is_local Imported.Family444V13.witnessStep7

end EncryptedResponseRegression
