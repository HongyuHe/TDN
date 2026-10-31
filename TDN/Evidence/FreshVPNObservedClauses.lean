import TDN.Import.Command
import TDN.Targets.VPNObservedClauses

namespace TDN.Imported.FreshVPNObservedClauses
open Targets

tdn_data certificates : List LoadedDeviceCertificate from "../../evidence/lean/FreshVPNObservedClauses.json" ["TDN.Imported.FreshVPNObservedClauses.certificates"]

tdn_data policies : List CertificateAuthenticationPolicy from "../../evidence/lean/FreshVPNObservedClauses.json" ["TDN.Imported.FreshVPNObservedClauses.policies"]

tdn_data espHardSeconds : List Nat from "../../evidence/lean/FreshVPNObservedClauses.json" ["TDN.Imported.FreshVPNObservedClauses.espHardSeconds"]

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
