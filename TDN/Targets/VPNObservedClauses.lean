import TDN.Targets.Cryptography
import Mathlib.Data.List.Nodup
import Lean.Elab.Tactic.Omega

namespace TDN.Targets

structure LoadedDeviceCertificate where
  device : String
  fingerprint : String
  deriving DecidableEq, Repr

/-- A duplicate-free imported fingerprint list rules out certificate reuse across
distinct devices. Loaded status and complete selected inventory are importer facts. -/
theorem distinct_loaded_certificates_from_fingerprint_inventory
    (certificates : List LoadedDeviceCertificate)
    (unique : (certificates.map LoadedDeviceCertificate.fingerprint).Nodup) :
    ∀ a ∈ certificates, ∀ b ∈ certificates,
      a.device ≠ b.device → a.fingerprint ≠ b.fingerprint := by
  intro a ha b hb different same
  have equal := List.inj_on_of_nodup_map unique ha hb same
  exact different (congrArg LoadedDeviceCertificate.device equal)

/-- A zero add-time limit is disabled in the selected XFRM interpretation.
Only positive hard lifetimes can establish VG14's finite maximum. -/
def PositiveESPLifetime (seconds : Nat) : Prop := 0 < seconds ∧ seconds ≤ 28800

/-- The hard expiration bounds every active association age under the standard
kernel expiration contract. Time values are elapsed seconds, not event indices. -/
theorem active_esp_age_below_required_maximum (hardSeconds ageSeconds : Nat)
    (configured : PositiveESPLifetime hardSeconds) (active : ageSeconds < hardSeconds) :
    ageSeconds < 28800 := by
  unfold PositiveESPLifetime at configured
  omega

structure CertificateAuthenticationPolicy where
  device : String
  peer : String
  localCertificate : String
  requiredPeerIdentity : String
  requiresPeerCertificate : Bool
  deriving DecidableEq, Repr

/-- The standard IKE implementation admits an authenticated peer only if its
configured required certificate verification succeeds. The predicate abstracts
that local admission rule, without inventing a certificate-check log. -/
def CertificatePeerAccepted (policy : CertificateAuthenticationPolicy)
    (certificateVerified : Bool) : Prop :=
  policy.requiresPeerCertificate = false ∨ certificateVerified = true

/-- Reciprocal configurations requiring certificate verification force both
checks to succeed in any mutually admitted session. Actual peer, identity and
loaded-credential bindings are checked separately in each concrete inventory. -/
theorem mutual_certificate_admission_requires_both_verifications
    (left right : CertificateAuthenticationPolicy)
    (requiresLeft : left.requiresPeerCertificate = true)
    (requiresRight : right.requiresPeerCertificate = true)
    (leftVerifiedRight rightVerifiedLeft : Bool)
    (leftAccepted : CertificatePeerAccepted left leftVerifiedRight)
    (rightAccepted : CertificatePeerAccepted right rightVerifiedLeft) :
    leftVerifiedRight = true ∧ rightVerifiedLeft = true := by
  constructor
  · rcases leftAccepted with disabled | verified
    · rw [requiresLeft] at disabled
      contradiction
    · exact verified
  · rcases rightAccepted with disabled | verified
    · rw [requiresRight] at disabled
      contradiction
    · exact verified

end TDN.Targets
