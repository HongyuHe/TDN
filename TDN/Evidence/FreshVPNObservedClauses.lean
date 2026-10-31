import TDN.Targets.VPNObservedClauses

namespace TDN.Imported.FreshVPNObservedClauses
open Targets

def certificates : List LoadedDeviceCertificate := [⟨"NF_I_A1", "a8cb9bee7080879b7743da5a7d166b3df569f7a6df1fdf9a4c56681fdd2d6285"⟩, ⟨"NF_I_A2", "f84b300af48c859348df3559f0217377346b8bd195014f8ebc5bb1701e7f92be"⟩, ⟨"NF_I_B1", "41f959450a6c6c4b3bbf5fddd7a1a6554c182b8f1d4d1e6038d8a0b9bd976378"⟩, ⟨"NF_I_B2", "d36f5bd117908401467ae757e7814b6bdf082f673449e66b017e265d6c983052"⟩, ⟨"NF_I_A3", "0f8404e26c23b41f828b09fab379e983f242351ef474a4aa86b639cad76edd9b"⟩, ⟨"NF_I_B3", "c36eeab86a474580ab7d7f19c474c353a0691f99bb66cfc23693c47b75fa58c4"⟩, ⟨"NF_I_A4", "33717fd9f9c95b6127408bd04d8a48f559213ea7bb0751ad210434d9de3249e0"⟩, ⟨"NF_I_B4", "74212c3aba4ffc272cc233c4819d148aedac2a971170fbd3b76afb881260e862"⟩]
def policies : List CertificateAuthenticationPolicy := [⟨"NF_I_A1", "NF_I_B1", "a8cb9bee7080879b7743da5a7d166b3df569f7a6df1fdf9a4c56681fdd2d6285", "NF_I_B1.msc.test", true⟩, ⟨"NF_I_A2", "NF_I_B2", "f84b300af48c859348df3559f0217377346b8bd195014f8ebc5bb1701e7f92be", "NF_I_B2.msc.test", true⟩, ⟨"NF_I_B1", "NF_I_A1", "41f959450a6c6c4b3bbf5fddd7a1a6554c182b8f1d4d1e6038d8a0b9bd976378", "NF_I_A1.msc.test", true⟩, ⟨"NF_I_B2", "NF_I_A2", "d36f5bd117908401467ae757e7814b6bdf082f673449e66b017e265d6c983052", "NF_I_A2.msc.test", true⟩, ⟨"NF_I_A3", "NF_I_B3", "0f8404e26c23b41f828b09fab379e983f242351ef474a4aa86b639cad76edd9b", "NF_I_B3.msc.test", true⟩, ⟨"NF_I_B3", "NF_I_A3", "c36eeab86a474580ab7d7f19c474c353a0691f99bb66cfc23693c47b75fa58c4", "NF_I_A3.msc.test", true⟩, ⟨"NF_I_A4", "NF_I_B4", "33717fd9f9c95b6127408bd04d8a48f559213ea7bb0751ad210434d9de3249e0", "NF_I_B4.msc.test", true⟩, ⟨"NF_I_B4", "NF_I_A4", "74212c3aba4ffc272cc233c4819d148aedac2a971170fbd3b76afb881260e862", "NF_I_A4.msc.test", true⟩]
def espHardSeconds : List Nat := [3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600]

lemma fingerprints_unique : (certificates.map LoadedDeviceCertificate.fingerprint).Nodup := by decide
lemma peer_verification_required : ∀ policy ∈ policies, policy.requiresPeerCertificate = true := by decide
lemma esp_lifetimes_positive_and_bounded : ∀ seconds ∈ espHardSeconds, PositiveESPLifetime seconds := by
  unfold PositiveESPLifetime
  decide

theorem loaded_certificates_are_unique_per_device :
    ∀ a ∈ certificates, ∀ b ∈ certificates, a.device ≠ b.device → a.fingerprint ≠ b.fingerprint :=
  distinct_loaded_certificates_from_fingerprint_inventory certificates fingerprints_unique

theorem every_selected_active_esp_age_is_below_eight_hours
    (hard age : Nat) (member : hard ∈ espHardSeconds) (active : age < hard) : age < 28800 :=
  active_esp_age_below_required_maximum hard age (esp_lifetimes_positive_and_bounded hard member) active

theorem admitted_selected_peers_require_mutual_certificate_verification
    (left right : CertificateAuthenticationPolicy) (hl : left ∈ policies) (hr : right ∈ policies)
    (leftVerifiedRight rightVerifiedLeft : Bool)
    (leftAccepted : CertificatePeerAccepted left leftVerifiedRight)
    (rightAccepted : CertificatePeerAccepted right rightVerifiedLeft) :
    leftVerifiedRight = true ∧ rightVerifiedLeft = true :=
  mutual_certificate_admission_requires_both_verifications left right
    (peer_verification_required left hl) (peer_verification_required right hr)
    leftVerifiedRight rightVerifiedLeft leftAccepted rightAccepted

lemma nonempty_selected_certificates_and_lifetimes : certificates.length = 8 ∧ espHardSeconds.length = 20 := by decide

end TDN.Imported.FreshVPNObservedClauses
