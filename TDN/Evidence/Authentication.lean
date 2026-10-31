import TDN.Import.Command
import TDN.Evidence.SupplementalTypes

namespace TDN.Imported.Authentication

set_option maxRecDepth 100000

tdn_data credentials : List (String × String × String × String) from "../../evidence/lean/Authentication.json" ["TDN.Imported.Authentication.credentials"]

theorem observed_credentials_and_configured_hash_constraints : credentials ≠ [] ∧ ∀ c ∈ credentials, c.2.1 = "secp384r1" ∧ c.2.2.1 = "ecdsa-384-sha384" ∧ c.2.2.2 = "ecdsa-384-sha384" := by unfold credentials; decide

tdn_data selectedSignatures : List (String × String) from "../../evidence/lean/Authentication.json" ["TDN.Imported.Authentication.selectedSignatures"]

theorem selected_authentication_uses_sha384 : selectedSignatures ≠ [] ∧ ∀ s ∈ selectedSignatures, s.1 = "ECDSA_WITH_SHA384_DER" ∧ s.2 = "ECDSA_WITH_SHA384_DER" := by unfold selectedSignatures; decide

tdn_data advertisedCapabilities : List (Bool × List Nat) from "../../evidence/lean/Authentication.json" ["TDN.Imported.Authentication.advertisedCapabilities"]

theorem observed_capabilities_distinguish_request_and_response : advertisedCapabilities ≠ [] ∧ ∀ a ∈ advertisedCapabilities, a.2 = (if a.1 then [2,3,4,5] else [3]) := by unfold advertisedCapabilities; decide

def trial : String × String × String × Nat := ("ECDSA_WITH_SHA256_DER", "signature scheme not acceptable", "ECDSA_WITH_SHA384_DER", 3)

theorem recorded_sha256_refusal_and_sha384_recovery : trial.1 = "ECDSA_WITH_SHA256_DER" ∧ trial.2.1 = "signature scheme not acceptable" ∧ trial.2.2.1 = "ECDSA_WITH_SHA384_DER" ∧ 0 < trial.2.2.2 := by unfold trial; decide

end TDN.Imported.Authentication
