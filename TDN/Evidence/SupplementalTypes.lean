import TDN.Evidence.MechanismTypes
namespace TDN.Evidence

/-- One instrumented TLS attempt. Certificate presence describes the test input. -/
structure TLSSample where
  caseId : String
  source : String
  target : String
  clientCertificate : Bool
  version : String
  cipher : String
  outcome : String
  certificateRequired : Bool
  deriving DecidableEq, Repr

def TLSRecordedOutcomes (samples : List TLSSample) : Prop :=
  samples ≠ [] ∧ ∀ s ∈ samples,
    s.version = "TLSv1.3" ∧ s.cipher = "TLS_AES_256_GCM_SHA384" ∧
    (s.clientCertificate = true → s.outcome = "delivered") ∧
    (s.clientCertificate = false → s.outcome = "rejected" ∧ s.certificateRequired = true)

/-- A reply sample does not assert clock adjustment or an authorized time source. -/
structure NTPReply where
  caseId : String
  server : String
  port : Nat
  mode : Nat
  stratum : Nat
  originMatches : Bool
  clockAdjusted : Bool
  deriving DecidableEq, Repr

def RecordedNTPReplies (samples : List NTPReply) : Prop :=
  samples ≠ [] ∧ ∀ s ∈ samples, s.port = 123 ∧ s.mode = 4 ∧
    0 < s.stratum ∧ s.stratum < 16 ∧ s.originMatches = true ∧ s.clockAdjusted = false

structure CAExchange where
  caseId : String
  localIdentity : String
  peerIdentity : String
  localSignature : String
  peerSignature : String
  peerStatus : String
  reachedRoot : Bool
  usefulReplies : Nat
  deriving DecidableEq, Repr

def RecordedCertificateExchanges (samples : List CAExchange) : Prop :=
  samples ≠ [] ∧ ∀ s ∈ samples,
    s.localIdentity ≠ s.peerIdentity ∧ s.localSignature = "ECDSA_WITH_SHA384_DER" ∧
    s.peerSignature = "ECDSA_WITH_SHA384_DER" ∧ s.peerStatus = "good" ∧
    s.reachedRoot = true ∧ 0 < s.usefulReplies

end TDN.Evidence
