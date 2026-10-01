import TDN.MSC.Configuration

/-!
# Sampled public credential identities

The export contains public certificate-list output from each encryptor. These
checks use every reported end-entity and CA record from that command. They bind
local and peer identities to their declared tunnel and compare reported public
key identifiers across trust domains. They do not validate signatures, read
private keys, prove key independence, or establish an exhaustive credential
store. Certificate validity and revocation execution remain separate obligations.
-/
namespace TDN.MSC
open Deployment

/-- Public identity fields are comparable across observations. The private-key
presence indicator is deliberately excluded: a peer's public certificate is
normally cached without the private key reported by its owning device. -/
def PublicCertificate.identity (c : PublicCertificate) : PublicCertificate :=
  { c with hasPrivateKey := false }

structure CredentialTriple where
  localCertificate : PublicCertificate
  peerCertificate : PublicCertificate
  caCertificate : PublicCertificate
  deriving DecidableEq, BEq, Repr

/-- The current profile reports one local certificate, one peer certificate,
and one CA per encryptor. Missing, extra, or ambiguous records produce `none`.
No unselected record is discarded to make the downstream checks succeed. -/
def credentialTriple? (owner : String) : Option CredentialTriple := do
  let inventory ← certificateInventories.find? (fun i => i.device == owner)
  let certificates ← inventory.certificates
  let [ca] := certificates.filter PublicCertificate.isCA | none
  let [first, second] := certificates.filter (fun c => !c.isCA) | none
  let tunnel ← tunnel? owner
  let localCertificate ← [first, second].find? (fun c => c.subject == "CN=" ++ owner ++ ".msc.test")
  let peerCertificate ← [first, second].find? (fun c => c.subject == "CN=" ++ tunnel.peer ++ ".msc.test")
  if localCertificate.subject == peerCertificate.subject then none
  else some ⟨localCertificate, peerCertificate, ca⟩

/-- Completeness is checked before any filterMap-based uniqueness result.
Every declared tunnel owner has one inventory and a complete credential triple.
The observation time is retained in the imported inventory, not replaced by the
proof-checking time. An unavailable command can never satisfy this theorem. -/
theorem sampled_credentials_complete :
    (certificateInventories.map CertificateInventory.device).Nodup ∧
    certificateInventories.length = tunnels.length ∧
    ∀ t ∈ tunnels, (credentialTriple? t.owner).isSome = true := by decide

/-- Exact subject and alternative-name checks bind the observed records to the
experiment's explicit identity naming convention. The local private-key flag
is only a reported presence indicator; it does not expose or authenticate a key. -/
theorem sampled_credentials_match_identities : ∀ t ∈ tunnels,
    ∃ c ∈ (credentialTriple? t.owner).toList,
      c.localCertificate.subject = "CN=" ++ t.owner ++ ".msc.test" ∧
      c.localCertificate.altNames = [t.owner ++ ".msc.test"] ∧
      c.localCertificate.hasPrivateKey = true ∧
      c.peerCertificate.subject = "CN=" ++ t.peer ++ ".msc.test" ∧
      c.peerCertificate.altNames = [t.peer ++ ".msc.test"] := by decide

/-- Reported issuer and authority-key identifiers connect both end entities to
the reported CA. Equality of metadata is not a certificate-signature check.
The expected CA subject derives from the tunnel's declared trust-domain name. -/
theorem sampled_certificates_match_ca_metadata : ∀ t ∈ tunnels,
    ∃ c ∈ (credentialTriple? t.owner).toList,
      c.caCertificate.subject = "CN=Twinet MSC " ++ t.trust ∧
      c.caCertificate.issuer = c.caCertificate.subject ∧
      c.localCertificate.issuer = c.caCertificate.subject ∧
      c.peerCertificate.issuer = c.caCertificate.subject ∧
      c.localCertificate.authorityKeyId = c.caCertificate.subjectKeyId ∧
      c.peerCertificate.authorityKeyId = c.caCertificate.subjectKeyId := by decide

/-- The peer certificate observed at one endpoint agrees with the local public
identity record observed at its declared peer. The samples need not be atomic. -/
theorem sampled_peer_certificate_identifiers_match : ∀ t ∈ tunnels,
    ∃ own ∈ (credentialTriple? t.owner).toList,
      ∃ peer ∈ (credentialTriple? t.peer).toList,
        own.peerCertificate.identity = peer.localCertificate.identity := by decide

/-- Equal declared trust domains have the same sampled public CA identity. -/
theorem sampled_trust_ca_identifiers_agree : ∀ a ∈ tunnels, ∀ b ∈ tunnels,
    a.trust = b.trust → ∃ ca ∈ (credentialTriple? a.owner).toList,
      ∃ cb ∈ (credentialTriple? b.owner).toList,
      ca.caCertificate.identity = cb.caCertificate.identity := by decide

/-- Different trust-domain labels correspond to distinct reported CA public-key
and subject-key identifiers. Combined with inner_trust_domains_separate, the
finite check grounds the declared S1/S2 distinction in sampled public metadata.
Identifier inequality does not prove distinct secret keys or cryptographic
collision resistance, and the inventory need not list every trust source. -/
theorem sampled_distinct_trust_ca_identifiers : ∀ a ∈ tunnels, ∀ b ∈ tunnels,
    a.trust ≠ b.trust → ∃ ca ∈ (credentialTriple? a.owner).toList,
      ∃ cb ∈ (credentialTriple? b.owner).toList,
      ca.caCertificate.keyId ≠ cb.caCertificate.keyId ∧
      ca.caCertificate.subjectKeyId ≠ cb.caCertificate.subjectKeyId := by decide

/-- Every encryptor's sampled local public-key identifier is distinct. The
completeness theorem above ensures that missing inventories cannot disappear
through filterMap and make a shorter list appear uniquely credentialed. -/
theorem sampled_local_certificate_identifiers_unique :
    (tunnels.filterMap (fun t =>
      (credentialTriple? t.owner).map (fun c => c.localCertificate.keyId))).Nodup := by decide

end TDN.MSC
