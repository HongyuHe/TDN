import TDN.Targets.Protocol

namespace TDN.Imported.FinalMACsecAlgorithms

/-- Exact source/runtime bindings and their implementation contract are in the import report. -/
def devices : List Targets.MACsecAlgorithms := [⟨0, "AES Key Wrap", 256, "AES GCM", 256⟩, ⟨1, "AES Key Wrap", 256, "AES GCM", 256⟩, ⟨2, "AES Key Wrap", 256, "AES GCM", 256⟩, ⟨3, "AES Key Wrap", 256, "AES GCM", 256⟩]
def publicVectorResults : List (String × String × String) := [("G1-128", "b57a0b05f43e9600c3c4d15c1e3c26e8", "b57a0b05f43e9600c3c4d15c1e3c26e8"), ("G1-256", "0efd01e5b03a0951a6df9bbffe419016ee40fdbfc3335ebf92ea03802214a307", "0efd01e5b03a0951a6df9bbffe419016ee40fdbfc3335ebf92ea03802214a307"), ("G2-128", "135bd758b0ee5c11c55ff6ab19fdb199", "135bd758b0ee5c11c55ff6ab19fdb199"), ("G2-256", "a29efdb63d6fba73c65daab2295340a837a8886e94a905b5c9c7ef1d9dbb297e", "a29efdb63d6fba73c65daab2295340a837a8886e94a905b5c9c7ef1d9dbb297e"), ("G3-128", "96437a93ccf10d9dfe347846cce52c7d", "96437a93ccf10d9dfe347846cce52c7d"), ("G3-256", "7888f5d48ba8b24e96bb95bd8c7304ec", "7888f5d48ba8b24e96bb95bd8c7304ec"), ("G4-128", "8f5a384c15d6ae9302b462e363d03ca6", "8f5a384c15d6ae9302b462e363d03ca6"), ("G4-256", "71340e454c84a1232aa7977d5ed86f78f250f3f9d53584b9337ff0c6dfdc9f96", "71340e454c84a1232aa7977d5ed86f78f250f3f9d53584b9337ff0c6dfdc9f96"), ("G5-128", "8f1c5cb1c8ed2e5f047906e0473aad4d", "8f1c5cb1c8ed2e5f047906e0473aad4d"), ("G5-256", "98b8544d7390a41e50ef72e25b4a036523c919e812918871949b48123eab526e", "98b8544d7390a41e50ef72e25b4a036523c919e812918871949b48123eab526e"), ("G6-128", "045205925831ae59c14550ed59cc003d", "045205925831ae59c14550ed59cc003d"), ("G6-256", "bb692568b287484a5f3f4793b09732270d13dd818373c15b3f2793fdc1948a37", "bb692568b287484a5f3f4793b09732270d13dd818373c15b3f2793fdc1948a37")]

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
