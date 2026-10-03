import TDN.Network.CredentialEvidence
import TDN.Network.Routing

/-!
Peer admission combines explicit identity policy with public credential evidence.
The policy accepts a request only after a trusted possession check, certificate
path verification, algorithm/usage checks, time checks, and fresh revocation
evidence. Labels describe policy rules; the admission function does not compare
labels. A separate finite certificate can therefore justify label preservation.

Certificate and CRL signature results are external trusted inputs. The theorem
concerns their correct use by the modeled admission procedure. The observation
record binds those results to public object fingerprints and a sampled clock.
-/
namespace TDN.Network.Authentication

structure AlgorithmProfile where
  keyAlgorithm : String
  keyBits : Nat
  curve : String
  signatureAlgorithm : String
  requiredUsages : List Nat
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure PeerRule (Label : Type) where
  localIdentity : String
  remoteIdentity : String
  anchor : String
  localLabel : Label
  remoteLabel : Label
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure Policy (Label : Type) where
  algorithm : AlgorithmProfile
  rules : List (PeerRule Label)
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

/-- The possession result comes from the trusted authentication operation for
this exact certificate. It cannot be inferred from a claimed identity string. -/
structure Request where
  localIdentity : String
  remoteIdentity : String
  certificate : String
  possessionVerified : Bool
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

variable {Label : Type}

def verifiedBy (values : List PublicVerification) (anchor : String) : Bool :=
  values.any (fun v => v.anchor == anchor && v.valid)

def credentialAlgorithm (profile : AlgorithmProfile) (certificate : CertificateEvidence) : Bool :=
  certificate.publicKeyAlgorithm == profile.keyAlgorithm && certificate.publicKeyBits == profile.keyBits &&
    certificate.curve == profile.curve && certificate.signatureAlgorithm == profile.signatureAlgorithm

def validAt (now : Nat) (certificate : CertificateEvidence) : Bool :=
  certificate.notBefore ≤ now && now ≤ certificate.notAfter

def anchorUsable (profile : AlgorithmProfile) (now : Nat) (anchor : CertificateEvidence) : Bool :=
  anchor.isCA && anchor.basicConstraintsValid && credentialAlgorithm profile anchor && validAt now anchor &&
    (anchor.keyUsage &&& 96) == 96 && anchor.unhandledCriticalExtensions.isEmpty

def certificateUsable (profile : AlgorithmProfile) (now : Nat) (identity : String)
    (anchor certificate : CertificateEvidence) : Bool :=
  !certificate.isCA && certificate.basicConstraintsValid && credentialAlgorithm profile certificate &&
    validAt now certificate && (certificate.keyUsage &&& 1) == 1 &&
    profile.requiredUsages.all certificate.extendedKeyUsage.contains &&
    certificate.unknownExtendedKeyUsage.isEmpty && certificate.unhandledCriticalExtensions.isEmpty &&
    certificate.dnsNames.contains identity && certificate.issuer == anchor.subject &&
    certificate.authorityKeyId == anchor.subjectKeyId &&
    verifiedBy certificate.verifications anchor.fingerprint

/-- Choose the newest authenticated CRL by number before checking freshness.
An expired newest CRL cannot cause fallback to an older, still-valid CRL. -/
def currentCRL (audit : CredentialAudit) (anchor : CertificateEvidence) : Option CRLEvidence :=
  Routing.select (fun a b => a.number > b.number || (a.number == b.number && a.thisUpdate > b.thisUpdate))
    (audit.crls.filter fun crl => crl.issuer == anchor.subject &&
      crl.authorityKeyId == anchor.subjectKeyId && verifiedBy crl.verifications anchor.fingerprint)

def revocationUsable (profile : AlgorithmProfile) (now : Nat)
    (certificate : CertificateEvidence) (crl : CRLEvidence) : Bool :=
  crl.signatureAlgorithm == profile.signatureAlgorithm && crl.thisUpdate ≤ now && now < crl.nextUpdate &&
    !crl.revokedSerials.contains certificate.serial

def acceptsRule (profile : AlgorithmProfile) (audit : CredentialAudit)
    (rule : PeerRule Label) (request : Request) : Bool :=
  rule.localIdentity == request.localIdentity && rule.remoteIdentity == request.remoteIdentity &&
    request.possessionVerified && audit.anchors.contains rule.anchor &&
    (audit.certificates.find? (fun c => c.fingerprint == rule.anchor)).any fun anchor =>
      anchorUsable profile audit.atEpoch anchor &&
      (audit.certificates.find? (fun c => c.fingerprint == request.certificate)).any fun certificate =>
        certificateUsable profile audit.atEpoch request.remoteIdentity anchor certificate &&
        (currentCRL audit anchor).any (revocationUsable profile audit.atEpoch certificate)

def admits (policy : Policy Label) (audit : CredentialAudit) (request : Request) : Bool :=
  policy.rules.any (fun rule => acceptsRule policy.algorithm audit rule request)

theorem admitted_has_declared_rule (policy : Policy Label) (audit : CredentialAudit) (request : Request)
    (accepted : admits policy audit request = true) :
    ∃ rule ∈ policy.rules, rule.localIdentity = request.localIdentity ∧
      rule.remoteIdentity = request.remoteIdentity ∧ acceptsRule policy.algorithm audit rule request = true := by
  simp only [admits, List.any_eq_true] at accepted
  obtain ⟨rule, member, checked⟩ := accepted
  refine ⟨rule, member, ?_, ?_, checked⟩ <;> simp_all [acceptsRule]

theorem unverified_possession_rejected (policy : Policy Label) (audit : CredentialAudit) (request : Request)
    (unverified : request.possessionVerified = false) : admits policy audit request = false := by
  simp [admits, acceptsRule, unverified]

theorem undeclared_peer_rejected (policy : Policy Label) (audit : CredentialAudit) (request : Request)
    (absent : ∀ rule ∈ policy.rules, rule.localIdentity ≠ request.localIdentity ∨
      rule.remoteIdentity ≠ request.remoteIdentity) : admits policy audit request = false := by
  apply Bool.eq_false_iff.mpr
  intro accepted
  obtain ⟨rule, member, localName, remoteName, _⟩ := admitted_has_declared_rule policy audit request accepted
  rcases absent rule member with localWrong | remoteWrong
  · exact localWrong localName
  · exact remoteWrong remoteName

/-- Labels are a policy consequence. Admission itself inspects identities and
credentials, while a caller supplies a separately checked rule-label invariant. -/
theorem admitted_rule_labels_agree (policy : Policy Label) (audit : CredentialAudit) (request : Request)
    (separated : ∀ rule ∈ policy.rules, rule.localLabel = rule.remoteLabel)
    (accepted : admits policy audit request = true) :
    ∃ rule ∈ policy.rules, rule.localIdentity = request.localIdentity ∧
      rule.remoteIdentity = request.remoteIdentity ∧ rule.localLabel = rule.remoteLabel := by
  obtain ⟨rule, member, localName, remoteName, _⟩ := admitted_has_declared_rule policy audit request accepted
  exact ⟨rule, member, localName, remoteName, separated rule member⟩

theorem accepted_certificate_is_current (profile : AlgorithmProfile) (now : Nat) (identity : String)
    (anchor certificate : CertificateEvidence)
    (accepted : certificateUsable profile now identity anchor certificate = true) :
    certificate.notBefore ≤ now ∧ now ≤ certificate.notAfter := by
  simp_all [certificateUsable, validAt]

theorem accepted_revocation_is_current_and_unrevoked (profile : AlgorithmProfile) (now : Nat)
    (certificate : CertificateEvidence) (crl : CRLEvidence)
    (accepted : revocationUsable profile now certificate crl = true) :
    crl.thisUpdate ≤ now ∧ now < crl.nextUpdate ∧ certificate.serial ∉ crl.revokedSerials := by
  simp_all [revocationUsable]

/-- Lift admission success to the exact observed certificate and selected CRL.
The result exposes the records needed by expiry, revocation, and trust theorems. -/
theorem admitted_credential_evidence (policy : Policy Label) (audit : CredentialAudit) (request : Request)
    (accepted : admits policy audit request = true) :
    ∃ anchor ∈ audit.certificates, ∃ certificate ∈ audit.certificates, ∃ crl ∈ audit.crls,
      certificate.fingerprint = request.certificate ∧
      anchorUsable policy.algorithm audit.atEpoch anchor = true ∧
      certificateUsable policy.algorithm audit.atEpoch request.remoteIdentity anchor certificate = true ∧
      currentCRL audit anchor = some crl ∧
      revocationUsable policy.algorithm audit.atEpoch certificate crl = true := by
  obtain ⟨rule, _, _, _, checked⟩ := admitted_has_declared_rule policy audit request accepted
  simp only [acceptsRule, Bool.and_eq_true, Option.any_eq_true] at checked
  obtain ⟨anchor, anchorFound, anchorGood, certificate, certificateFound, certificateGood,
    crl, crlFound, crlGood⟩ := checked.2
  have crlMember := Routing.selected_is_member _ _ crl crlFound
  refine ⟨anchor, List.mem_of_find?_eq_some anchorFound,
    certificate, List.mem_of_find?_eq_some certificateFound,
    crl, (List.mem_filter.mp crlMember).1, ?_, anchorGood, certificateGood, crlFound, crlGood⟩
  simpa using List.find?_some certificateFound

/-- Every fully admitted request passes certificate and selected-CRL time
checks and is absent from that CRL's revocation set. -/
theorem admitted_peer_is_current_and_unrevoked (policy : Policy Label) (audit : CredentialAudit) (request : Request)
    (accepted : admits policy audit request = true) :
    ∃ certificate ∈ audit.certificates, ∃ crl ∈ audit.crls,
      certificate.fingerprint = request.certificate ∧
      certificate.notBefore ≤ audit.atEpoch ∧ audit.atEpoch ≤ certificate.notAfter ∧
      crl.thisUpdate ≤ audit.atEpoch ∧ audit.atEpoch < crl.nextUpdate ∧
      certificate.serial ∉ crl.revokedSerials := by
  obtain ⟨anchor, _, certificate, member, crl, crlMember, fingerprint, _, current, _, fresh⟩ :=
    admitted_credential_evidence policy audit request accepted
  have validity := accepted_certificate_is_current policy.algorithm audit.atEpoch _ anchor certificate current
  have revocation := accepted_revocation_is_current_and_unrevoked policy.algorithm audit.atEpoch certificate crl fresh
  exact ⟨certificate, member, crl, crlMember, fingerprint, validity.1, validity.2, revocation⟩

theorem expired_peer_rejected (policy : Policy Label) (audit : CredentialAudit) (request : Request)
    (expired : ∀ certificate ∈ audit.certificates, certificate.fingerprint = request.certificate →
      certificate.notAfter < audit.atEpoch) : admits policy audit request = false := by
  apply Bool.eq_false_iff.mpr
  intro accepted
  obtain ⟨certificate, member, _, _, identity, _, current, _⟩ :=
    admitted_peer_is_current_and_unrevoked policy audit request accepted
  have past := expired certificate member identity
  omega

theorem stale_crls_rejected (policy : Policy Label) (audit : CredentialAudit) (request : Request)
    (stale : ∀ crl ∈ audit.crls, crl.nextUpdate ≤ audit.atEpoch) : admits policy audit request = false := by
  apply Bool.eq_false_iff.mpr
  intro accepted
  obtain ⟨_, _, crl, member, _, _, _, _, fresh, _⟩ :=
    admitted_peer_is_current_and_unrevoked policy audit request accepted
  have past := stale crl member
  omega

end TDN.Network.Authentication
