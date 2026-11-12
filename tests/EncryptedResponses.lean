import TDN.Models.BlockRepliesToLocalCiphertext
import TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4_V13_SampleTrace

namespace EncryptedResponseRegression
open TDN TDN.DataPlaneForwarding TDN.EncryptedResponseGuards

def association : IpsecPolicy := ⟨10, 1, 100, 200, 1, 10, 11, 20, 0, none⟩

/-- A broad ICMP allowance cannot establish encrypted-error output denial. -/
example : ¬ TableDrivenDeny [{
    egressPolicies := [association],
    outputRules := [⟨[.protocol "icmp"], .allow⟩] }] := by
  unfold TableDrivenDeny
  native_decide
/-- A reply destination interval disjoint from the local wire source is sufficient. -/
example : TableDrivenDeny [{
    egressPolicies := [association],
    outputRules := [⟨[.protocol "icmp", .destinationRange 200 200], .allow⟩] }] := by
  unfold TableDrivenDeny
  native_decide
/-- A permissive fallback is detected even if no allow rule exists. -/
example : ¬ TableDrivenDeny [{ egressPolicies := [association], outputFallback := .allow }] := by
  unfold TableDrivenDeny
  native_decide
/-- The actual positive path reaches the new post-encryption generation class. -/
example : LocallyEncrypted Deployments.DualStack_RedV4_GrayV4_BlackV4_V13.config Deployments.DualStack_RedV4_GrayV4_BlackV4_V13.witnessState8 :=
  encryption_step_is_local Deployments.DualStack_RedV4_GrayV4_BlackV4_V13.witnessStep7

end EncryptedResponseRegression
