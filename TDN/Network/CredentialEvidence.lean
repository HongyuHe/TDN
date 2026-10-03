import TDN.Network.IPv4

/-!
Public credential evidence describes observations and trusted library results.
The exporter records public PEM objects and verifies certificate paths and CRL
signatures using Go's X.509 library. Lean receives the results as data and checks
the admission policy that uses them. Cryptographic signature correctness and
the observed clock remain explicit external dependencies. Private keys are
absent from every record below.
-/
namespace TDN.Network

structure PublicVerification where
  anchor : String
  valid : Bool
  error : String
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure CertificateEvidence where
  fingerprint : String
  subject : String
  issuer : String
  serial : String
  notBefore : Nat
  notAfter : Nat
  publicKeyAlgorithm : String
  publicKeyBits : Nat
  curve : String
  signatureAlgorithm : String
  isCA : Bool
  basicConstraintsValid : Bool
  keyUsage : Nat
  extendedKeyUsage : List Nat
  unknownExtendedKeyUsage : List String
  unhandledCriticalExtensions : List String
  dnsNames : List String
  subjectKeyId : String
  authorityKeyId : String
  verifications : List PublicVerification
  /-- Missing metadata remains unknown. An observed empty list establishes
  that this public certificate advertises no retrieval location of that kind. -/
  crlDistributionPoints : Option (List String) := none
  ocspServers : Option (List String) := none
  issuingCertificateURLs : Option (List String) := none
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure CRLEvidence where
  fingerprint : String
  issuer : String
  authorityKeyId : String
  thisUpdate : Nat
  nextUpdate : Nat
  number : Nat
  signatureAlgorithm : String
  revokedSerials : List String
  verifications : List PublicVerification
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure CredentialAudit where
  atEpoch : Nat
  pemSHA256 : String
  anchors : List String
  certificates : List CertificateEvidence
  crls : List CRLEvidence
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure LoadedChildConnection where
  name : String
  mode : String
  rekeySeconds : Nat
  rekeyBytes : Nat
  rekeyPackets : Nat
  dpdAction : String
  closeAction : String
  localSelectors : List Prefix
  remoteSelectors : List Prefix
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

/-- The inventory contains every loaded connection and child. The lists allow
multiple peers and selectors; no single matching row hides an additional row. -/
structure LoadedConnection where
  name : String
  version : Nat
  reauthIntervalSeconds : Nat
  ikeRekeyIntervalSeconds : Nat
  dpdSeconds : Nat
  localAddresses : List UInt32
  remoteAddresses : List UInt32
  localAuth : String
  localIdentity : String
  localCertificate : String
  remoteAuth : String
  remoteIdentity : String
  remoteCA : String
  revocation : String
  uniquePolicy : String
  children : List LoadedChildConnection
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure ChildSession where
  name : String
  uniqueId : Nat
  reqid : Nat
  state : String
  mode : String
  /-- Retain the complete daemon report. An absent separate exchange group is
  meaningful: an initial IKEv2 CHILD inherits IKE key material. The report alone
  does not prove which exchange created the CHILD or establish separate DH. -/
  proposal : String
  installedSeconds : Nat
  rekeySeconds : Nat
  expiresSeconds : Nat
  inboundSPI : Nat
  outboundSPI : Nat
  inboundBytes : Nat
  outboundBytes : Nat
  inboundPackets : Nat
  outboundPackets : Nat
  inboundLastSeconds : Option Nat
  outboundLastSeconds : Option Nat
  localSelectors : List Prefix
  remoteSelectors : List Prefix
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

/-- Rekey overlap may produce several IKE or CHILD records. Each record keeps
its own endpoints, selectors, public identifiers, timers, and counters. -/
structure IkeSession where
  name : String
  uniqueId : Nat
  state : String
  version : Nat
  initiatorSPI : String
  responderSPI : String
  initiator : Bool
  responder : Bool
  localIdentity : String
  remoteIdentity : String
  localAddress : UInt32
  remoteAddress : UInt32
  localPort : Nat
  remotePort : Nat
  proposal : String
  establishedSeconds : Nat
  reauthSeconds : Option Nat
  ikeRekeySeconds : Option Nat
  children : List ChildSession
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure ReportedRevocation where
  serial : String
  atEpoch : Nat
  reason : String
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure ReportedCRL where
  issuer : String
  thisUpdate : Nat
  nextUpdate : Nat
  thisUpdateStatus : String
  nextUpdateStatus : String
  number : Nat
  authorityKeyId : String
  revoked : List ReportedRevocation
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure AuthorityConfiguration where
  name : String
  certificate : String
  crlURIs : List String
  ocspURIs : List String
  certificateURIBase : String
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure AuthenticationObservation where
  device : String
  observedAt : String
  audit : Option CredentialAudit
  reportedCRLs : Option (List ReportedCRL)
  connections : Option (List LoadedConnection)
  sessions : Option (List IkeSession)
  authorities : Option (List AuthorityConfiguration) := none
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

end TDN.Network
