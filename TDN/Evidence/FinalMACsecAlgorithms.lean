import TDN.Import.Command
import TDN.Targets.Protocol

namespace TDN.Imported.FinalMACsecAlgorithms

/-- Exact source/runtime bindings and their implementation contract are in the import report. -/
tdn_data devices : List Targets.MACsecAlgorithms from "../../evidence/lean/FinalMACsecAlgorithms.json" ["TDN.Imported.FinalMACsecAlgorithms.devices"]

tdn_data publicVectorResults : List (String × String × String) from "../../evidence/lean/FinalMACsecAlgorithms.json" ["TDN.Imported.FinalMACsecAlgorithms.publicVectorResults"]

lemma nonempty_devices : devices ≠ [] := by decide
lemma key_distribution_checks : ∀ device ∈ devices,
    device.keyWrapAlgorithm = "AES Key Wrap" ∧ device.keyWrapBits = 256 := by decide
lemma data_protection_checks : ∀ device ∈ devices,
    device.protectionAlgorithm = "AES GCM" ∧ device.protectionBits = 256 := by decide

theorem selected_runtime_algorithms :
    Targets.msc_macsec_encryption_and_key_wrap devices :=
  Targets.macsec_algorithms_from_local_checks devices key_distribution_checks data_protection_checks

/-- Finite public test outputs, with no universal KDF correctness claim. -/
theorem twelve_public_vectors_match : publicVectorResults.length = 12 ∧
    ∀ result ∈ publicVectorResults, result.2.1 = result.2.2 := by decide

end TDN.Imported.FinalMACsecAlgorithms
