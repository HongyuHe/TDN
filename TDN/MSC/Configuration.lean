import TDN.MSC.Contracts

/-!
# Checked intended IPsec settings

The importer reads explicit settings from hashed intended strongSwan files.
The following finite proofs check those records and their relationship to the
separately declared tunnels. They do not prove which settings the daemon loaded
or which algorithms every future session will negotiate.
-/
namespace TDN.MSC
open Deployment

/-- Eight distinct files cover every declared tunnel endpoint. Matching fields
prevent a correct-looking configuration for another peer from serving as the
configuration evidence for the tunnel in question. -/
theorem crypto_configs_complete : cryptoConfigs.length = 8 ∧
    (cryptoConfigs.map CryptoConfig.device).Nodup ∧
    (∀ t ∈ tunnels, ∃ c ∈ cryptoConfigs,
      c.device = t.owner ∧ c.localAddress = t.localAddress ∧
      c.remoteAddress = t.remoteAddress ∧ c.localSelector = t.localSelector ∧
      c.remoteSelector = t.remoteSelector ∧ c.reqid = t.reqid) := by decide

/-- VG-9 and the selected IPsec architecture receive a configuration-level
check: IKE version 2 and ESP tunnel mode are explicitly selected everywhere. -/
theorem intended_ikev2_tunnel_mode : ∀ c ∈ cryptoConfigs,
    c.version = 2 ∧ c.mode = "tunnel" := by decide

/-- Both sides request public-key authentication, with explicit local certificate
and remote CA references. The strings identify intended credential files.
Their contents and daemon authentication behavior are not validated here.
Together with completeness, the check covers all eight endpoint configurations. -/
theorem intended_certificate_authentication : ∀ c ∈ cryptoConfigs,
    c.localAuth = "pubkey" ∧ c.remoteAuth = "pubkey" ∧
      c.localCertificate.isEmpty = false ∧ c.remoteCA.isEmpty = false := by decide

/-- The explicit remote revocation setting is strict at every endpoint. Actual
certificate-path validation, CRL freshness, and revocation failure behavior
remain separate execution obligations under VG-7. -/
theorem intended_strict_revocation : ∀ c ∈ cryptoConfigs,
    c.revocation = "strict" := by decide

/-- Node-1 uses the device-name.msc.test identity convention, also checked in
the sampled SA parser. Each intended file names its declared local device and
peer, so a wildcard peer identity cannot satisfy this predicate. The CP does
not mandate that spelling; it is the selected experiment's identity policy.
Matching intended names does not authenticate possession of a private key. -/
theorem intended_peer_identities : ∀ t ∈ tunnels, ∃ c ∈ cryptoConfigs,
    c.device = t.owner ∧ c.localIdentity = t.owner ++ ".msc.test" ∧
      c.remoteIdentity = t.peer ++ ".msc.test" := by decide

/-- The declared proposal alternatives are AES-256-GCM, SHA-384 PRF, and P-384
key exchange. These strings check the offered configuration portion of VG-1,
VG-12, and VG-18. They do not establish certificate algorithms, implementation
correctness, product approval, or the separate CNSA 2.0 alternative. -/
theorem intended_gcm_proposals : ∀ c ∈ cryptoConfigs,
    c.ikeProposal = "aes256gcm16-prfsha384-ecp384" ∧
    c.espProposal = "aes256gcm16-ecp384" := by decide

/-- The supported profile disables IKE rekeying and schedules reauthentication.
Under strongSwan's documented interpretation, over_time is a relative overrun
allowance and randomization subtracts from the scheduled time. Thus reauth plus
overrun gives the configured upper bound used for VG-13: 3h + 10m < 24h.
This arithmetic theorem is about intended settings, not execution of timers.
Source: https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html -/
theorem intended_ike_lifetime_bound : ∀ c ∈ cryptoConfigs,
    0 < c.reauthSeconds ∧ c.ikeRekeySeconds = 0 ∧
      c.reauthSeconds + c.overSeconds ≤ 24 * 3600 := by decide

/-- The configured hard CHILD lifetime is positive and within VG-14's 8h bound.
The snapshot sets 1h. No claim about clock reliability follows from the record. -/
theorem intended_child_lifetime_bound : ∀ c ∈ cryptoConfigs,
    0 < c.childLifeSeconds ∧ c.childLifeSeconds ≤ 8 * 3600 := by decide

end TDN.MSC
