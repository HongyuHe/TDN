import TDN.MSC.Credentials
import TDN.MSC.Operational
import TDN.Network.Authentication

/-!
The MSC admission instance derives peer rules from every loaded connection.
Observed public credentials and signature-check results provide the candidate
certificates, selected trust anchors, and CRLs. Finite proofs compare the loaded
settings with the declared tunnels and intended settings. They cover every
observed session and XFRM SA, so an extra wrong-peer session cannot hide behind
one healthy session. Optional management credentials are outside this inventory.
-/
namespace TDN.MSC.Authentication

-- Nested finite evidence relations need more instance nodes than the default.
set_option synthInstance.maxSize 512
open Deployment
open TDN.Network (CredentialAudit AuthenticationObservation CertificateEvidence LoadedConnection IkeSession)
open TDN.Network.Authentication

-- Go's X.509 usage identifiers 1 and 2 mean server and client authentication.
-- The selected CNSA 1.0 certificate profile uses P-384 and SHA-384.
def algorithm : AlgorithmProfile :=
  { keyAlgorithm := "ECDSA", keyBits := 384, curve := "P-384",
    signatureAlgorithm := "ECDSA-SHA384", requiredUsages := [1, 2] }

def observation? (owner : String) : Option AuthenticationObservation :=
  authenticationObservations.find? (fun o => o.device == owner)

def audit? (owner : String) : Option CredentialAudit :=
  (observation? owner).bind AuthenticationObservation.audit

def connections (owner : String) : List LoadedConnection :=
  ((observation? owner).bind AuthenticationObservation.connections).getD []

def sessions (owner : String) : List IkeSession :=
  ((observation? owner).bind AuthenticationObservation.sessions).getD []

def identityLevel (identity : String) : Option SecurityLevel :=
  (devices.find? (fun device => device.id ++ ".msc.test" == identity)).bind Device.level

/-- Normalize byte-oriented serial text to the integer's hexadecimal spelling.
Leading zero nibbles affect formatting, while the numeric serial stays equal. -/
def serialHex (serial : String) : String :=
  let digits := (serial.toList.filter (· != ':')).dropWhile (· == '0')
  if digits.isEmpty then "0" else String.ofList digits

/-- A selected anchor must be both observed and present in the configured public
trust file. Peer identities come from loaded daemon settings, not an MSC host-pair
allowlist. All loaded connections contribute a rule or fail completeness below. -/
def peerRule? (audit : CredentialAudit) (connection : LoadedConnection) : Option (PeerRule (Option SecurityLevel)) := do
  let anchor ← audit.certificates.find? (fun c => c.isCA && c.subject == connection.remoteCA && audit.anchors.contains c.fingerprint)
  pure
    { localIdentity := connection.localIdentity, remoteIdentity := connection.remoteIdentity,
      anchor := anchor.fingerprint, localLabel := identityLevel connection.localIdentity,
      remoteLabel := identityLevel connection.remoteIdentity }

def policy (owner : String) : Policy (Option SecurityLevel) :=
  { algorithm := algorithm, rules := ((audit? owner).map fun audit =>
      (connections owner).filterMap (peerRule? audit)).getD [] }

/-- The ESTABLISHED IKE state supplies the trusted peer-possession result.
The request still has to pass all identity, path, validity, and revocation checks.
The symbolic model does not recover or reverify the IKE authentication signature. -/
def sessionRequest? (audit : CredentialAudit) (session : IkeSession) : Option Request := do
  let certificate ← audit.certificates.find? (fun c => !c.isCA && c.dnsNames.contains session.remoteIdentity)
  pure
    { localIdentity := session.localIdentity, remoteIdentity := session.remoteIdentity,
      certificate := certificate.fingerprint, possessionVerified := session.state == "ESTABLISHED" }

theorem authentication_observations_complete :
    (authenticationObservations.map AuthenticationObservation.device).Nodup ∧
    authenticationObservations.length = tunnels.length ∧
    ∀ t ∈ tunnels,
      (audit? t.owner).isSome = true ∧
      (connections t.owner).length = 1 ∧ (sessions t.owner).isEmpty = false ∧
      (policy t.owner).rules.length = (connections t.owner).length := by decide

/-- The raw daemon inventory exposes the revocation status requirement GOOD.
The human-readable inventory independently supplies addresses and identities;
the importer rejects disagreement between the two observed representations. -/
theorem loaded_connections_match_intent : ∀ t ∈ tunnels, ∀ c ∈ connections t.owner,
    c.version = 2 ∧ c.localAddresses.map some = [ipv4? t.localAddress] ∧
    c.remoteAddresses.map some = [ipv4? t.remoteAddress] ∧
    c.localIdentity = t.owner ++ ".msc.test" ∧ c.remoteIdentity = t.peer ++ ".msc.test" ∧
    c.localAuth = "public key" ∧ c.remoteAuth = "public key" ∧ c.revocation = "GOOD" ∧
    c.localCertificate = "CN=" ++ t.owner ++ ".msc.test" ∧ c.remoteCA = "CN=Twinet MSC " ++ t.trust ∧
    c.children.length = 1 ∧
    (∀ child ∈ c.children, child.mode = "TUNNEL" ∧
      child.localSelectors.map some = [Prefix.parse? t.localSelector] ∧
      child.remoteSelectors.map some = [Prefix.parse? t.remoteSelector] ∧
      child.rekeyBytes = 0 ∧ child.rekeyPackets = 0) ∧
    (∃ config ∈ cryptoConfigs, config.device = t.owner ∧
      c.reauthIntervalSeconds = config.reauthSeconds ∧ c.ikeRekeyIntervalSeconds = config.ikeRekeySeconds ∧
      ∀ child ∈ c.children, 0 < child.rekeySeconds ∧ child.rekeySeconds < config.childLifeSeconds) := by decide

/-- Every parsed human-readable certificate is bound to a verified public PEM
record by subject, serial, public-key algorithm/size, validity, and key IDs.
Changed expiry or RSA-512 metadata cannot disappear during translation. -/
theorem public_certificate_views_agree : ∀ t ∈ tunnels,
    ∀ inventory ∈ certificateInventories, inventory.device = t.owner →
    ∀ record ∈ inventory.certificates.getD [],
    ∀ audit ∈ (audit? t.owner).toList,
    ∃ certificate ∈ audit.certificates,
      certificate.subject = record.subject ∧ certificate.issuer = record.issuer ∧
      certificate.serial = serialHex record.serial ∧
      certificate.publicKeyAlgorithm = record.publicKeyAlgorithm ∧ certificate.publicKeyBits = record.publicKeyBits ∧
      certificate.notBefore = record.notBefore ∧ certificate.notAfter = record.notAfter ∧
      record.notBeforeStatus = "ok" ∧ record.notAfterStatus = "ok" ∧
      certificate.isCA = record.isCA ∧
      (certificate.subjectKeyId = "" ∨ certificate.subjectKeyId = String.ofList (record.subjectKeyId.toList.filter (· != ':'))) ∧
      certificate.authorityKeyId = String.ofList (record.authorityKeyId.toList.filter (· != ':')) ∧
      (if record.isCA then record.usageFlags = ["CA", "CRLSign", "self-signed"]
       else record.usageFlags = ["serverAuth", "clientAuth"]) := by decide

/-- The textual CRL inventory and verified PEM inventory agree in both count
and contents. Removing a reported CRL cannot be masked by another observation. -/
theorem public_crl_views_agree : ∀ observation ∈ authenticationObservations,
    observation.reportedCRLs.isSome = true ∧
    ∀ audit ∈ observation.audit.toList,
      (observation.reportedCRLs.getD []).length = audit.crls.length ∧
      ∀ reported ∈ observation.reportedCRLs.getD [], ∃ crl ∈ audit.crls,
        reported.issuer = crl.issuer ∧ reported.authorityKeyId = crl.authorityKeyId ∧
        reported.thisUpdate = crl.thisUpdate ∧ reported.nextUpdate = crl.nextUpdate ∧
        reported.thisUpdateStatus = "ok" ∧ reported.nextUpdateStatus = "ok" ∧
        reported.number = crl.number ∧
        (reported.revoked.map TDN.Network.ReportedRevocation.serial).Perm crl.revokedSerials := by decide

/-- The selected flat CA hierarchy has one anchor and one current CRL per
endpoint. Every observed end entity is usable under that anchor, including the
local certificate and the cached peer certificate. No extra public record is
excluded from the finite check. -/
theorem sampled_public_credentials_usable : ∀ t ∈ tunnels, ∀ audit ∈ (audit? t.owner).toList,
    audit.anchors.length = 1 ∧ audit.certificates.length = 3 ∧ audit.crls.length = 1 ∧
    (audit.certificates.map CertificateEvidence.fingerprint).Nodup ∧
    ∀ anchorId ∈ audit.anchors, ∃ anchor ∈ audit.certificates,
      anchor.fingerprint = anchorId ∧ anchor.subject = "CN=Twinet MSC " ++ t.trust ∧
      anchorUsable algorithm audit.atEpoch anchor = true ∧
      ∀ certificate ∈ audit.certificates, certificate.isCA = false →
        certificate.subject ≠ certificate.issuer ∧
        certificate.basicConstraintsValid = true ∧ (certificate.keyUsage &&& 1) = 1 ∧
        algorithm.requiredUsages.all certificate.extendedKeyUsage.contains = true ∧
        certificate.unhandledCriticalExtensions = [] ∧ certificate.unknownExtendedKeyUsage = [] ∧
        credentialAlgorithm algorithm certificate = true ∧
        validAt audit.atEpoch certificate = true ∧
        verifiedBy certificate.verifications anchorId = true ∧
        ∀ crl ∈ audit.crls,
          crl.issuer = anchor.subject ∧ crl.authorityKeyId = anchor.subjectKeyId ∧
          verifiedBy crl.verifications anchorId = true ∧
          revocationUsable algorithm audit.atEpoch certificate crl = true := by decide

/-- The peer's cached public certificate is byte-identified by the same SHA-256
fingerprint as the certificate observed at the owning endpoint. Equal subject
strings alone do not supply this evidence. -/
theorem sampled_peer_public_objects_match : ∀ t ∈ tunnels,
    ∀ localAudit ∈ (audit? t.owner).toList, ∀ peerAudit ∈ (audit? t.peer).toList,
    ∀ certificate ∈ localAudit.certificates,
      certificate.subject = "CN=" ++ t.peer ++ ".msc.test" →
      ∃ peerCertificate ∈ peerAudit.certificates,
        peerCertificate.subject = certificate.subject ∧
        peerCertificate.fingerprint = certificate.fingerprint := by decide

/-- The selected trust-domain names correspond to complete public CA objects.
Different trust domains have different anchors; equal domains share an anchor. -/
theorem sampled_anchor_objects_match_trust_domains : ∀ a ∈ tunnels, ∀ b ∈ tunnels,
    ∀ auditA ∈ (audit? a.owner).toList, ∀ auditB ∈ (audit? b.owner).toList,
      (a.trust = b.trust → auditA.anchors = auditB.anchors) ∧
      (a.trust ≠ b.trust → ∀ anchorA ∈ auditA.anchors, ∀ anchorB ∈ auditB.anchors,
        anchorA ≠ anchorB) := by decide

/-- The name-to-level mapping is checked on every inner rule. Level equality
is absent from `admits`, so the generic label theorem uses a real finite premise. -/
theorem inner_peer_rules_preserve_level : ∀ t ∈ tunnels, role? t.owner = some .inner →
    ∀ rule ∈ (policy t.owner).rules,
      rule.localLabel.isSome = true ∧ rule.localLabel = rule.remoteLabel := by decide

theorem peer_rule_labels_match_identities : ∀ t ∈ tunnels, ∀ rule ∈ (policy t.owner).rules,
    identityLevel rule.localIdentity = rule.localLabel ∧
    identityLevel rule.remoteIdentity = rule.remoteLabel := by decide

/-- All observed sessions must satisfy a loaded connection and the declared
peer/selectors. The universal quantifier detects an added wrong-level session.
The parent IKE proposal must include the selected P-384 exchange. A CHILD report
must select AES-256-GCM and may either omit a separate exchange or report P-384.
IKE_AUTH initially derives CHILD keys from IKE key material, so strongSwan
normally omits the separate exchange in that report. The observation alone
does not distinguish initial creation from a later CHILD exchange without DH.
The disjunction therefore checks reported algorithms without claiming that
every CHILD performed an independent P-384 exchange. Intended rekey proposals
are checked separately by `intended_gcm_proposals`. -/
theorem sampled_sessions_match_declared_peers : ∀ t ∈ tunnels,
    (sessions t.owner |>.map IkeSession.uniqueId).Nodup ∧
    ∀ session ∈ sessions t.owner,
      session.state = "ESTABLISHED" ∧ session.version = 2 ∧
      session.localIdentity = t.owner ++ ".msc.test" ∧ session.remoteIdentity = t.peer ++ ".msc.test" ∧
      some session.localAddress = ipv4? t.localAddress ∧ some session.remoteAddress = ipv4? t.remoteAddress ∧
      session.proposal = "AES_GCM_16-256/PRF_HMAC_SHA2_384/ECP_384" ∧ session.children.isEmpty = false ∧
      ∀ child ∈ session.children, child.reqid = t.reqid ∧ child.state = "INSTALLED" ∧ child.mode = "TUNNEL" ∧
        (child.proposal = "AES_GCM_16-256" ∨ child.proposal = "AES_GCM_16-256/ECP_384") ∧
        child.localSelectors.map some = [Prefix.parse? t.localSelector] ∧
        child.remoteSelectors.map some = [Prefix.parse? t.remoteSelector] := by decide

/-- Sampled reauthentication remains scheduled, IKE rekey is disabled, and
observed CHILD installation-age plus remaining lifetime respects the configured
hard bound. These are sampled timer facts; future scheduling remains external. -/
theorem sampled_authentication_lifetimes : ∀ t ∈ tunnels, ∀ c ∈ connections t.owner,
    0 < c.reauthIntervalSeconds ∧ c.ikeRekeyIntervalSeconds = 0 ∧
    ∀ session ∈ sessions t.owner, session.ikeRekeySeconds = none ∧ session.reauthSeconds.isSome = true ∧
      (∀ remaining ∈ session.reauthSeconds.toList,
        session.establishedSeconds + remaining ≤ c.reauthIntervalSeconds) ∧
      ∀ child ∈ session.children, child.installedSeconds + child.expiresSeconds ≤ 28800 := by decide

/-- Credential verification and the container's sampled clock use the worker
clock within the observed collection interval. The bound permits sequential
commands. Absolute UTC accuracy remains a trusted experimental assumption. -/
theorem credential_clocks_match_runtime : ∀ t ∈ tunnels, ∀ audit ∈ (audit? t.owner).toList,
    ((operational? t.owner).bind TDN.Network.OperationalSnapshot.clockEpoch).isSome = true ∧
    ∀ clock ∈ ((operational? t.owner).bind TDN.Network.OperationalSnapshot.clockEpoch).toList,
      clock ≤ audit.atEpoch ∧ audit.atEpoch ≤ clock + 5 := by decide

/-- Both positive admission and universal session coverage matter. The intended
peer has a complete request and passes the same policy used in rejection lemmas. -/
theorem every_sampled_peer_is_admitted : ∀ t ∈ tunnels, ∀ audit ∈ (audit? t.owner).toList,
    ∀ session ∈ sessions t.owner,
      (sessionRequest? audit session).isSome = true ∧
      ∀ request ∈ (sessionRequest? audit session).toList,
        admits (policy t.owner) audit request = true := by decide

/-- Every kernel SA belongs to a listed CHILD session in its actual direction.
That connection binds data-plane encryption state to the checked peer inventory. -/
theorem sampled_xfrm_states_belong_to_sessions : ∀ t ∈ tunnels,
    ∀ state ∈ liveStates t.owner, ∃ session ∈ sessions t.owner, ∃ child ∈ session.children,
      state.reqid = child.reqid ∧
      ((state.source = session.localAddress ∧ state.destination = session.remoteAddress ∧ state.spi = child.outboundSPI) ∨
       (state.source = session.remoteAddress ∧ state.destination = session.localAddress ∧ state.spi = child.inboundSPI)) := by decide

/-- Combine the finite SA/session binding with the checked admission policy.
Every sampled data-plane SA has an associated complete admitted peer request. -/
theorem sampled_xfrm_state_has_admitted_peer (t : Tunnel) (member : t ∈ tunnels)
    (audit : CredentialAudit) (auditMember : audit ∈ (audit? t.owner).toList)
    (state : TDN.Network.XfrmState) (stateMember : state ∈ liveStates t.owner) :
    ∃ session ∈ sessions t.owner, ∃ child ∈ session.children,
      state.reqid = child.reqid ∧
      ((state.source = session.localAddress ∧ state.destination = session.remoteAddress ∧ state.spi = child.outboundSPI) ∨
       (state.source = session.remoteAddress ∧ state.destination = session.localAddress ∧ state.spi = child.inboundSPI)) ∧
      ∃ request, sessionRequest? audit session = some request ∧ admits (policy t.owner) audit request = true := by
  obtain ⟨session, sessionMember, child, childMember, reqid, endpoints⟩ :=
    sampled_xfrm_states_belong_to_sessions t member state stateMember
  obtain ⟨present, accepted⟩ := every_sampled_peer_is_admitted t member audit auditMember session sessionMember
  cases request : sessionRequest? audit session with
  | none => simp [request] at present
  | some value =>
    exact ⟨session, sessionMember, child, childMember, reqid, endpoints,
      value, request, accepted value (by simpa using request)⟩

/-- VG-15's peer-admission contribution covers arbitrary presented requests.
Only the loaded and checked inner peer rules can admit a request, and those
rules preserve the complete security label. Possession and signature checks
remain the explicit trusted authentication operations. -/
theorem admitted_inner_peer_has_same_level (t : Tunnel) (member : t ∈ tunnels)
    (inner : role? t.owner = some .inner) (audit : CredentialAudit) (request : Request)
    (accepted : admits (policy t.owner) audit request = true) :
    ∃ rule ∈ (policy t.owner).rules, rule.localIdentity = request.localIdentity ∧
      rule.remoteIdentity = request.remoteIdentity ∧ rule.localLabel = rule.remoteLabel :=
  admitted_rule_labels_agree (policy t.owner) audit request
    (fun rule ruleMember => (inner_peer_rules_preserve_level t member inner rule ruleMember).2) accepted

/-- The public conclusion names the request's actual endpoint identities and
requires a known local label. Two unknown names cannot satisfy the conclusion. -/
theorem admitted_inner_identity_levels_equal (t : Tunnel) (member : t ∈ tunnels)
    (inner : role? t.owner = some .inner) (audit : CredentialAudit) (request : Request)
    (accepted : admits (policy t.owner) audit request = true) :
    (identityLevel request.localIdentity).isSome = true ∧
    identityLevel request.localIdentity = identityLevel request.remoteIdentity := by
  obtain ⟨rule, ruleMember, localName, remoteName, same⟩ :=
    admitted_inner_peer_has_same_level t member inner audit request accepted
  obtain ⟨localLabel, remoteLabel⟩ := peer_rule_labels_match_identities t member rule ruleMember
  rw [← localName, ← remoteName, localLabel, remoteLabel]
  exact ⟨(inner_peer_rules_preserve_level t member inner rule ruleMember).1, same⟩

end TDN.MSC.Authentication
