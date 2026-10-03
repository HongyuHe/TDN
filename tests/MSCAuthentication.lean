import TDN
open TDN.Network TDN.Network.Authentication
open TDN.MSC.Authentication

namespace MSCAuthenticationRegression

def observed : CredentialAudit := (audit? "I_A1").getD
  { atEpoch := 0, pemSHA256 := "", anchors := [], certificates := [], crls := [] }

def request : Request := ((sessions "I_A1").head?.bind (sessionRequest? observed)).getD
  { localIdentity := "", remoteIdentity := "", certificate := "", possessionVerified := false }

def alteredPeer (change : CertificateEvidence → CertificateEvidence) : CredentialAudit :=
  { observed with certificates := observed.certificates.map fun c =>
      if c.fingerprint == request.certificate then change c else c }

example : admits (policy "I_A1") observed request = true := by decide
example : admits (policy "I_A1") observed { request with possessionVerified := false } = false := by decide
example : admits (policy "I_A1") observed { request with remoteIdentity := "I_B2.msc.test" } = false := by decide
example : admits (policy "I_A1") (alteredPeer fun c => { c with notAfter := observed.atEpoch - 1 }) request = false := by decide
example : admits (policy "I_A1") (alteredPeer fun c => { c with notBefore := observed.atEpoch + 1 }) request = false := by decide
example : admits (policy "I_A1") (alteredPeer fun c => { c with issuer := "CN=another authority" }) request = false := by decide
example : admits (policy "I_A1") (alteredPeer fun c => { c with authorityKeyId := "wrong" }) request = false := by decide
example : admits (policy "I_A1") (alteredPeer fun c => { c with publicKeyAlgorithm := "RSA", publicKeyBits := 512 }) request = false := by decide
example : admits (policy "I_A1") (alteredPeer fun c => { c with keyUsage := 0 }) request = false := by decide
example : admits (policy "I_A1") (alteredPeer fun c => { c with verifications := [] }) request = false := by decide
example : admits (policy "I_A1") { observed with crls := [] } request = false := by decide
example : admits (policy "I_A1") { observed with anchors := [] } request = false := by decide

/-- A signed CRL that revokes the presented certificate blocks admission. -/
example : admits (policy "I_A1") { observed with crls := observed.crls.map fun crl =>
    { crl with revokedSerials := observed.certificates.map CertificateEvidence.serial } } request = false := by decide

example : admits (policy "I_A1") { observed with crls := observed.crls.map fun crl =>
    { crl with nextUpdate := observed.atEpoch } } request = false := by decide

/-- A newer expired CRL cannot be bypassed by selecting an older fresh CRL. -/
example : admits (policy "I_A1") { observed with crls := observed.crls ++ observed.crls.map fun crl =>
    { crl with number := crl.number + 1, nextUpdate := observed.atEpoch } } request = false := by decide

/-- A newer revocation also overrides an older list without that revocation. -/
example : admits (policy "I_A1") { observed with crls := observed.crls ++ observed.crls.map fun crl =>
    { crl with number := crl.number + 1, revokedSerials := observed.certificates.map CertificateEvidence.serial } } request = false := by decide

end MSCAuthenticationRegression
