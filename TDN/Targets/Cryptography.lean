import TDN.Targets.Protocol
import TDN.Targets.Architecture

namespace TDN.Targets

inductive SignatureAlgorithm where
  | rsa3072 | ecdsaP384sha384 | mldsa87 | other
  deriving DecidableEq, Repr

inductive KeyEstablishment where
  | ecdhP384 | dh3072 | dh4096 | mlkem1024 | other
  deriving DecidableEq, Repr

inductive IntegrityAlgorithm where
  | sha384 | sha512 | other
  deriving DecidableEq, Repr

structure AlgorithmSuite where
  aesBits : Nat
  gcm : Bool
  signature : SignatureAlgorithm
  establishment : KeyEstablishment
  integrity : IntegrityAlgorithm
  deriving DecidableEq, Repr

def ClassicalEstablishment (k : KeyEstablishment) : Prop :=
  k = .ecdhP384 ∨ k = .dh3072 ∨ k = .dh4096

def ApprovedIntegrity (i : IntegrityAlgorithm) : Prop := i = .sha384 ∨ i = .sha512

/-- Table 6 and Table 10 permit DH4096 in their detailed protocol profiles. -/
def CNSA1 (suite : AlgorithmSuite) : Prop :=
  suite.aesBits = 256 ∧
  (suite.signature = .rsa3072 ∨ suite.signature = .ecdsaP384sha384) ∧
  ClassicalEstablishment suite.establishment ∧ ApprovedIntegrity suite.integrity

def CNSA2 (suite : AlgorithmSuite) : Prop :=
  suite.aesBits = 256 ∧ suite.gcm = true ∧ suite.signature = .mldsa87 ∧
  suite.establishment = .mlkem1024 ∧ ApprovedIntegrity suite.integrity

/-- RG-018 records the section-2 choices and explicit protocol refinements.
Optional firmware signing is specified separately in RG-073. -/
def msc_cnss_algorithm_policy (suites : List AlgorithmSuite) : Prop :=
  ∀ suite ∈ suites, CNSA1 suite ∨ CNSA2 suite

inductive IKEKind where
  | initial | intermediate | authentication
  deriving DecidableEq, Repr

structure IKEOperation where
  kind : IKEKind
  time : Nat
  establishment : KeyEstablishment
  encrypted : Bool
  encryptedUnderInitialKeys : Bool
  ipPacketBytes : List Nat
  pathMtu : Nat
  deriving DecidableEq, Repr

structure VPNProfile where
  objective : Bool
  proposals : List AlgorithmSuite
  operations : List IKEOperation
  rfc7383 : Bool
  rfc9242 : Bool
  rfc9370 : Bool
  cnsa2ProfileConformant : Bool
  deriving DecidableEq, Repr

def ObjectiveExchangeSequence (operations : List IKEOperation) : Prop :=
  (∃ initial ∈ operations, initial.kind = .initial) ∧
  (∃ intermediate ∈ operations, intermediate.kind = .intermediate) ∧
  (∀ initial ∈ operations, initial.kind = .initial →
    ClassicalEstablishment initial.establishment ∧ initial.ipPacketBytes ≠ [] ∧
    ∀ size ∈ initial.ipPacketBytes, size ≤ initial.pathMtu) ∧
  (∀ intermediate ∈ operations, intermediate.kind = .intermediate →
    intermediate.establishment = .mlkem1024 ∧ intermediate.encrypted = true ∧
    intermediate.encryptedUnderInitialKeys = true ∧
    (∃ initial ∈ operations, initial.kind = .initial ∧ initial.time < intermediate.time) ∧
    ∀ authentication ∈ operations, authentication.kind = .authentication →
      intermediate.time < authentication.time)

/-- RG-019 retains the joint VG-19/20/21 objective, all offered suites, and the
classical initial-exchange exception. Profile conformance includes referenced extensions. -/
def msc_ipsec_algorithm_profile_choice (profiles : List VPNProfile) : Prop :=
  ∀ profile ∈ profiles, profile.proposals ≠ [] ∧
    if profile.objective then
      (∀ suite ∈ profile.proposals, CNSA2 suite) ∧
      ObjectiveExchangeSequence profile.operations ∧
      profile.rfc7383 = true ∧ profile.rfc9242 = true ∧ profile.rfc9370 = true ∧
      profile.cnsa2ProfileConformant = true
    else ∀ suite ∈ profile.proposals, CNSA1 suite

/-- Any negotiated choice drawn from an approved offer set inherits its profile constraints. -/
theorem negotiated_suite_inherits_profile (offered : List AlgorithmSuite)
    (profile : AlgorithmSuite → Prop) (checked : ∀ suite ∈ offered, profile suite)
    (negotiated : AlgorithmSuite) (selected : negotiated ∈ offered) : profile negotiated :=
  checked negotiated selected

/-- The endpoint certificate presented by a device. CA chain certificates are represented
separately and are not subject to endpoint uniqueness or VG-2/VG-3 removal rules. -/
structure EndpointCertificate where
  device : String
  fingerprint : String
  npe : Bool
  issuerChain : List String
  trustAnchor : String
  factoryDefault : Bool
  selfSigned : Bool
  proprietary : Bool
  loaded : Bool
  removed : Bool
  deriving DecidableEq, Repr

/-- A trust anchor may legitimately be self-signed. Trust approval and chain validation
are separate requirements; self-signature alone does not make a CA an endpoint credential. -/
structure TrustAnchorCertificate where
  fingerprint : String
  ca : Bool
  selfSigned : Bool
  deriving DecidableEq, Repr

structure CertificateAuthentication where
  gateway : String
  certificateFingerprint : String
  duringIKE : Bool
  revocationChecked : Bool
  revoked : Bool
  expiryChecked : Bool
  expired : Bool
  deriving DecidableEq, Repr

structure MutualPeerAuthentication where
  left : String
  right : String
  methodAppropriate : Bool
  leftVerifiedRight : Bool
  rightVerifiedLeft : Bool
  deriving DecidableEq, Repr

/-- RG-017 includes every issued authentication certificate, not only sampled sessions. -/
def msc_mutual_device_authentication_and_npe (peers : List MutualPeerAuthentication)
    (issued : List EndpointCertificate) : Prop :=
  (∀ peer ∈ peers, peer.methodAppropriate = true ∧
    peer.leftVerifiedRight = true ∧ peer.rightVerifiedLeft = true) ∧
  ∀ certificate ∈ issued, certificate.npe = true

def DisallowedEndpointCertificate (certificate : EndpointCertificate) : Prop :=
  certificate.factoryDefault = true ∨ certificate.selfSigned = true ∨ certificate.proprietary = true

/-- RG-020 keeps complete loaded chains, unique certificates, every actual IKE check,
and the threshold/objective factory-certificate alternative. The endpoint list is the complete
in-scope device-credential inventory, including unused credentials when removal is selected.
INT-020 distinguishes these credentials from their corresponding CA chains. -/
def msc_vpn_certificate_authentication (gateways : List String)
    (certificates : List EndpointCertificate) (trustAnchors : List TrustAnchorCertificate)
    (authentications : List CertificateAuthentication)
    (removeFactoryObjective : Bool) (validChain : EndpointCertificate → Prop) : Prop :=
  (∀ gateway ∈ gateways, ∃ certificate ∈ certificates,
    certificate.device = gateway ∧ certificate.loaded = true ∧
    certificate.trustAnchor ∈ certificate.issuerChain ∧ validChain certificate ∧
    ∃ root ∈ trustAnchors, root.fingerprint = certificate.trustAnchor ∧ root.ca = true) ∧
  (∀ a ∈ certificates, ∀ b ∈ certificates, a.loaded = true → b.loaded = true →
    a.device ≠ b.device → a.fingerprint ≠ b.fingerprint) ∧
  (∀ authentication ∈ authentications, authentication.gateway ∈ gateways →
    authentication.duringIKE = true ∧ authentication.revocationChecked = true ∧
    authentication.revoked = false ∧ authentication.expiryChecked = true ∧
    authentication.expired = false ∧
    ∃ certificate ∈ certificates, certificate.device = authentication.gateway ∧
      certificate.fingerprint = authentication.certificateFingerprint ∧
      ¬ DisallowedEndpointCertificate certificate) ∧
  (removeFactoryObjective = true → ∀ certificate ∈ certificates,
    DisallowedEndpointCertificate certificate → certificate.removed = true)

/-- RG-021 quantifies every modeled interface extraction attempt and optional MAC access. -/
def msc_vpn_private_key_confinement {Key Principal Interface : Type}
    (gateway : Key → Principal) (interfaceExtracts : Interface → Key → Prop)
    (canAccess : Principal → Key → Prop) (macObjective : Bool) : Prop :=
  (∀ interface key, ¬ interfaceExtracts interface key) ∧
  (macObjective = true → ∀ principal key, canAccess principal key → principal = gateway key)

inductive MACsecAuthentication where
  | psk | eapTLS
  deriving DecidableEq, Repr

structure MACsecAuthenticationChoice where
  device : String
  method : MACsecAuthentication
  authenticatedWithCAK : Bool
  eapTLSMutualCertificateAuthentication : Bool
  performsSupplicantFunction : Bool
  performsAuthenticatorFunction : Bool
  authenticationServer : Option String
  serverConnectedSites : List String
  serverProvidesMutualAuthentication : Bool
  keyManagementAnnexMet : Bool
  symmetricKeyAnnexMet : Bool
  deriving DecidableEq, Repr

/-- RG-024 retains method-specific AS and annex applicability. INT024 requires each
certificate-based device to perform both roles across its supported arrangements; the source
does not require simultaneous operation in both roles. -/
def msc_macsec_authentication_choice_and_as (choices : List MACsecAuthenticationChoice) : Prop :=
  ∀ choice ∈ choices, match choice.method with
    | .psk => choice.authenticatedWithCAK = true ∧ choice.symmetricKeyAnnexMet = true
    | .eapTLS => choice.eapTLSMutualCertificateAuthentication = true ∧
      choice.performsSupplicantFunction = true ∧ choice.performsAuthenticatorFunction = true ∧
      choice.authenticationServer ≠ none ∧ choice.serverConnectedSites.length = 1 ∧
      choice.serverProvidesMutualAuthentication = true ∧ choice.keyManagementAnnexMet = true

structure EAPProfile where
  objective : Bool
  tlsMajor : Nat
  tlsMinor : Nat
  deviceSuites : List AlgorithmSuite
  serverSuites : List AlgorithmSuite
  rfc9190Conformant : Bool
  cnsa2TLSProfileConformant : Bool
  deriving DecidableEq, Repr

/-- RG-026 applies the chosen suite to both MACsec device and AS. The objective also
requires TLS1.3 and the cited EAP/TLS profile. -/
def msc_macsec_eap_tls_profile_choice (profiles : List EAPProfile) : Prop :=
  ∀ p ∈ profiles, p.deviceSuites ≠ [] ∧ p.serverSuites ≠ [] ∧
    if p.objective then
      p.tlsMajor = 1 ∧ p.tlsMinor = 3 ∧ p.rfc9190Conformant = true ∧
      p.cnsa2TLSProfileConformant = true ∧
      (∀ suite ∈ p.deviceSuites ++ p.serverSuites, CNSA2 suite)
    else ∀ suite ∈ p.deviceSuites ++ p.serverSuites, CNSA1 suite ∧ suite.gcm = true

structure MACsecKeyPair where
  leftSite : String
  rightSite : String
  leftPriority : Nat
  rightPriority : Nat
  centralSite : Option String
  cknBytes : Nat
  cknGeneratedByApprovedKGS : Bool
  cakGeneratedByApprovedKGS : Bool
  leftFallbackEnabled : Bool
  rightFallbackEnabled : Bool
  deriving DecidableEq, Repr

/-- RG-027 includes KGS approval, CKN length, asymmetric 0/1 priority, central key-server
selection when applicable, and disabled fallback CAKs. -/
def msc_macsec_key_generation_and_server (pairs : List MACsecKeyPair) : Prop :=
  ∀ pair ∈ pairs, 16 ≤ pair.cknBytes ∧ pair.cknGeneratedByApprovedKGS = true ∧
    pair.cakGeneratedByApprovedKGS = true ∧
    ((pair.leftPriority = 0 ∧ pair.rightPriority = 1) ∨
      (pair.leftPriority = 1 ∧ pair.rightPriority = 0)) ∧
    (∀ central, pair.centralSite = some central →
      (pair.leftSite = central ∧ pair.leftPriority = 0) ∨
      (pair.rightSite = central ∧ pair.rightPriority = 0)) ∧
    pair.leftFallbackEnabled = false ∧ pair.rightFallbackEnabled = false

inductive FirmwareSignature where
  | lms (parameters : String)
  | xmss (parameters : String)
  | mldsa (category parameter : Nat)
  | other
  deriving DecidableEq, Repr

def ApprovedFirmwareSignature (sp800208Approved : String → Prop) : FirmwareSignature → Prop
  | .lms parameters => sp800208Approved parameters
  | .xmss parameters => sp800208Approved parameters
  | .mldsa category parameter => category = 5 ∧ parameter = 87
  | .other => False

/-- RG-073 is optional and permits one of the Table2 alternatives for each component.
The LMS SHA256/192 preference remains a recommendation, not a requirement. -/
def msc_software_firmware_signature_choice (selected : Bool)
    (components : List String) (used : String → List FirmwareSignature)
    (sp800208Approved : String → Prop) : Prop :=
  selected = true → ∀ component ∈ components,
    (used component) ≠ [] ∧ ∀ signature ∈ used component,
      ApprovedFirmwareSignature sp800208Approved signature

end TDN.Targets
