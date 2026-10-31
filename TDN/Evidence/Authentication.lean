import TDN.Evidence.SupplementalTypes

namespace TDN.Imported.Authentication

set_option maxRecDepth 100000

def credentials : List (String × String × String × String) := [("I_A1", "secp384r1", "ecdsa-384-sha384", "ecdsa-384-sha384"), ("I_A2", "secp384r1", "ecdsa-384-sha384", "ecdsa-384-sha384"), ("I_B1", "secp384r1", "ecdsa-384-sha384", "ecdsa-384-sha384"), ("I_B2", "secp384r1", "ecdsa-384-sha384", "ecdsa-384-sha384"), ("O_A1", "secp384r1", "ecdsa-384-sha384", "ecdsa-384-sha384"), ("O_A2", "secp384r1", "ecdsa-384-sha384", "ecdsa-384-sha384"), ("O_B1", "secp384r1", "ecdsa-384-sha384", "ecdsa-384-sha384"), ("O_B2", "secp384r1", "ecdsa-384-sha384", "ecdsa-384-sha384")]

theorem observed_credentials_and_configured_hash_constraints : credentials ≠ [] ∧ ∀ c ∈ credentials, c.2.1 = "secp384r1" ∧ c.2.2.1 = "ecdsa-384-sha384" ∧ c.2.2.2 = "ecdsa-384-sha384" := by unfold credentials; decide

def selectedSignatures : List (String × String) := [("ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER"), ("ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER"), ("ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER"), ("ECDSA_WITH_SHA384_DER", "ECDSA_WITH_SHA384_DER")]

theorem selected_authentication_uses_sha384 : selectedSignatures ≠ [] ∧ ∀ s ∈ selectedSignatures, s.1 = "ECDSA_WITH_SHA384_DER" ∧ s.2 = "ECDSA_WITH_SHA384_DER" := by unfold selectedSignatures; decide

def advertisedCapabilities : List (Bool × List Nat) := [(false, [3]), (true, [2, 3, 4, 5]), (false, [3]), (true, [2, 3, 4, 5]), (false, [3]), (true, [2, 3, 4, 5]), (false, [3]), (true, [2, 3, 4, 5]), (false, [3]), (true, [2, 3, 4, 5]), (true, [2, 3, 4, 5]), (false, [3]), (true, [2, 3, 4, 5]), (true, [2, 3, 4, 5]), (false, [3]), (true, [2, 3, 4, 5]), (false, [3]), (false, [3]), (true, [2, 3, 4, 5]), (false, [3])]

theorem observed_capabilities_distinguish_request_and_response : advertisedCapabilities ≠ [] ∧ ∀ a ∈ advertisedCapabilities, a.2 = (if a.1 then [2,3,4,5] else [3]) := by unfold advertisedCapabilities; decide

def trial : String × String × String × Nat := ("ECDSA_WITH_SHA256_DER", "signature scheme not acceptable", "ECDSA_WITH_SHA384_DER", 3)

theorem recorded_sha256_refusal_and_sha384_recovery : trial.1 = "ECDSA_WITH_SHA256_DER" ∧ trial.2.1 = "signature scheme not acceptable" ∧ trial.2.2.1 = "ECDSA_WITH_SHA384_DER" ∧ 0 < trial.2.2.2 := by unfold trial; decide

end TDN.Imported.Authentication
