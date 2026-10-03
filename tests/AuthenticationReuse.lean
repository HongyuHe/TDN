import TDN.Network.Authentication

/-!
An independent fixture has three labeled peer pairs and one policy with multiple
rules. Public verification flags are synthetic trusted-checker inputs in this
unit test. The deployed MSC positive witnesses use exported real public objects.
No MSC module, device count, site type, or security-level enumeration is imported.
-/
namespace AuthenticationReuse
open TDN.Network TDN.Network.Authentication

def suite : AlgorithmProfile :=
  { keyAlgorithm := "ECDSA", keyBits := 384, curve := "P-384", signatureAlgorithm := "ECDSA-SHA384", requiredUsages := [1, 2] }

def certificate (name : String) : CertificateEvidence :=
  { fingerprint := name, subject := name, issuer := "CA", serial := name,
    notBefore := 10, notAfter := 1000, publicKeyAlgorithm := "ECDSA", publicKeyBits := 384,
    curve := "P-384", signatureAlgorithm := "ECDSA-SHA384", isCA := false, basicConstraintsValid := true,
    keyUsage := 1, extendedKeyUsage := [1, 2], unknownExtendedKeyUsage := [], unhandledCriticalExtensions := [],
    dnsNames := [name], subjectKeyId := name, authorityKeyId := "ca-key",
    verifications := [{ anchor := "root", valid := true, error := "" }] }

def root : CertificateEvidence :=
  { certificate "CA" with fingerprint := "root", isCA := true, keyUsage := 96, subjectKeyId := "ca-key" }

def revocation : CRLEvidence :=
  { fingerprint := "crl", issuer := "CA", authorityKeyId := "ca-key", thisUpdate := 50,
    nextUpdate := 500, number := 1, signatureAlgorithm := "ECDSA-SHA384", revokedSerials := [],
    verifications := [{ anchor := "root", valid := true, error := "" }] }

def evidence : CredentialAudit :=
  { atEpoch := 100, pemSHA256 := "synthetic fixture", anchors := ["root"],
    certificates := root :: [certificate "peer-a", certificate "peer-b", certificate "peer-c"],
    crls := [revocation] }

def rules : Policy Nat :=
  { algorithm := suite, rules :=
    [⟨"gateway-a", "peer-a", "root", 10, 10⟩,
     ⟨"gateway-b", "peer-b", "root", 20, 20⟩,
     ⟨"gateway-c", "peer-c", "root", 30, 30⟩] }

def request (gateway peer : String) : Request := ⟨gateway, peer, peer, true⟩

example : ∀ pair ∈ [("gateway-a", "peer-a"), ("gateway-b", "peer-b"), ("gateway-c", "peer-c")],
    admits rules evidence (request pair.1 pair.2) = true := by decide

example : admits rules evidence (request "gateway-a" "peer-b") = false := by decide
example : admits rules { evidence with atEpoch := 1001 } (request "gateway-a" "peer-a") = false := by decide

example (query : Request) (accepted : admits rules evidence query = true) :
    ∃ rule ∈ rules.rules, rule.localIdentity = query.localIdentity ∧
      rule.remoteIdentity = query.remoteIdentity ∧ rule.localLabel = rule.remoteLabel :=
  admitted_rule_labels_agree rules evidence query (by decide) accepted

end AuthenticationReuse
