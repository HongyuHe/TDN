import TDN.Requirements.CertificateAuthorityBindings
import TDN.Import.SnapshotLoader

namespace TDN.Deployments.NestedProtection
open Compliance Requirements.Msc

structure PublicAuthenticationBinding where
  device : String
  authorityId : String
  certificateAuthenticated : Bool
  preSharedCAKAuthenticated : Bool
  localAuth : String
  remoteAuth : String
  epoch : String
  phase : String
  ikeUniqueId : String
  childUniqueId : String
  peerDevice : String
  configObservation : String
  saObservation : String
  authenticationLogObservation : String
  authenticationSAObservation : String
  caObservation : String
  leafObservation : String
  loadedCertificatesObservation : String
  loadedConnectionObservation : String
  certificateDirectory : String
  certificateFile : String
  trustDirectory : String
  trustFile : String
  publicIssuerSignaturesChecked : Bool
  authoritySha256 : String
  authorityIsCA : Bool
  authorityKeyCertSign : Bool
  authorityDer : String
  localCertificateDer : String
  peerCertificateDer : String

def PublicAuthenticationBinding.setting (record : PublicAuthenticationBinding) : CertificateAuthoritySetting :=
  { component := record.device, authority := record.authorityId,
    certificateAuthenticated := record.certificateAuthenticated,
    preSharedCAKAuthenticated := record.preSharedCAKAuthenticated,
    authorityIsCA := record.authorityIsCA, authorityKeyCertSign := record.authorityKeyCertSign }

def PublicAuthenticationBinding.Check (record : PublicAuthenticationBinding) (epoch : String) : Prop :=
  record.setting.Check ∧ record.device ≠ "" ∧ record.peerDevice ≠ "" ∧
  record.certificateAuthenticated = true ∧ record.localAuth = "ecdsa-384-sha384" ∧
  record.remoteAuth = "ecdsa-384-sha384" ∧ record.epoch = epoch ∧
  record.phase ∈ ["phase-0", "phase-1"] ∧ record.ikeUniqueId ≠ "" ∧ record.childUniqueId ≠ "" ∧
  record.configObservation ≠ "" ∧ record.saObservation ≠ "" ∧
  record.authenticationLogObservation ≠ "" ∧ record.authenticationSAObservation ≠ "" ∧
  record.caObservation ≠ "" ∧ record.leafObservation ≠ "" ∧
  record.loadedCertificatesObservation ≠ "" ∧ record.loadedConnectionObservation ≠ "" ∧
  record.certificateDirectory = "/etc/swanctl/x509" ∧ record.certificateFile = "cert.pem" ∧
  record.trustDirectory = "/etc/swanctl/x509ca" ∧ record.trustFile = "ca.pem" ∧
  record.publicIssuerSignaturesChecked = true ∧ record.authorityId = "ca-sha256:" ++ record.authoritySha256 ∧
  record.authoritySha256.length = 64 ∧ record.authorityDer ≠ "" ∧
  record.localCertificateDer ≠ "" ∧ record.peerCertificateDer ≠ ""

end TDN.Deployments.NestedProtection
