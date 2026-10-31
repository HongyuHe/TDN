import TDN.Semantics.Temporal

namespace TDN.Targets

inductive CipherMode where
  | cbc | gcm | other
  deriving DecidableEq, Repr

structure VPNConfig where
  device : Nat
  ikeVersion : Nat
  ikeMode : CipherMode
  espMode : CipherMode
  espHmacIntegrity : Bool
  deriving DecidableEq, Repr

/-- A negotiated-session subset, distinct from the complete loaded RG-022 policy. -/
def NegotiatedModesConform (gateways : List VPNConfig) : Prop :=
  ∀ g ∈ gateways,
    g.ikeVersion = 2 ∧
    (g.ikeMode = .cbc ∨ g.ikeMode = .gcm) ∧
    ((g.espMode = .cbc ∧ g.espHmacIntegrity = true) ∨ g.espMode = .gcm)

structure ESPModeProposal where
  mode : CipherMode
  hmacIntegrity : Bool
  deriving DecidableEq, Repr

structure VPNModePolicy where
  device : String
  ikeVersions : List Nat
  ikeModes : List CipherMode
  espProposals : List ESPModeProposal
  deriving DecidableEq, Repr

/-- RG-022 at a complete loaded-configuration snapshot, with independent alternatives. -/
def msc_ike_version_and_encryption_modes (gateways : List VPNModePolicy) : Prop :=
  ∀ g ∈ gateways,
    g.ikeVersions ≠ [] ∧ (∀ version ∈ g.ikeVersions, version = 2) ∧
    g.ikeModes ≠ [] ∧ (∀ mode ∈ g.ikeModes, mode = .cbc ∨ mode = .gcm) ∧
    g.espProposals ≠ [] ∧
    (∀ proposal ∈ g.espProposals,
      (proposal.mode = .cbc ∧ proposal.hmacIntegrity = true) ∨ proposal.mode = .gcm)

structure VPNLifetimes where
  device : Nat
  ikeLifetimeSeconds : Nat
  espLifetimeSeconds : Nat
  deriving DecidableEq, Repr

/-- RG-023. Event coverage and configuration inventory are explicit external obligations. -/
def msc_vpn_sa_lifetimes_and_reauthentication
    (gateways : List VPNLifetimes) (events : List Temporal.Event) : Prop :=
  (∀ g ∈ gateways, g.ikeLifetimeSeconds ≤ 86400 ∧ g.espLifetimeSeconds ≤ 28800) ∧
  Temporal.RekeyDiscipline events

structure MACsecAlgorithms where
  device : Nat
  keyWrapAlgorithm : String
  keyWrapBits : Nat
  protectionAlgorithm : String
  protectionBits : Nat
  deriving DecidableEq, Repr

/-- RG-025. Both independent algorithm obligations are included. -/
def msc_macsec_encryption_and_key_wrap (devices : List MACsecAlgorithms) : Prop :=
  ∀ d ∈ devices,
    d.keyWrapAlgorithm = "AES Key Wrap" ∧ d.keyWrapBits = 256 ∧
    d.protectionAlgorithm = "AES GCM" ∧ d.protectionBits = 256

structure MACsecProtection where
  device : Nat
  dataDelayProtection : Bool
  lifetimeMilliseconds : Nat
  helloMilliseconds : Nat
  replayWindow : Nat
  feasibleReplayWindow : Nat → Prop
  confidentialityOffset : Nat
  mustSecure : Bool
  externalDataEvents : List Bool

/-- RG-028. Replay-window feasibility and observed event coverage are not invented. -/
def msc_macsec_protection_parameters (devices : List MACsecProtection) : Prop :=
  ∀ d ∈ devices,
    d.dataDelayProtection = true ∧
    d.lifetimeMilliseconds = 6000 ∧ d.helloMilliseconds = 2000 ∧
    (d.replayWindow = 2 ∨
      (d.feasibleReplayWindow d.replayWindow ∧
        ∀ w, d.feasibleReplayWindow w → d.replayWindow ≤ w)) ∧
    (∀ encrypted ∈ d.externalDataEvents, encrypted = true) ∧
    d.confidentialityOffset = 0 ∧ d.mustSecure = true

/-- A complete finite configuration check proves precisely the configuration clause. -/
theorem vpn_modes_of_checked_inventory (gateways : List VPNConfig)
    (version : ∀ g ∈ gateways, g.ikeVersion = 2)
    (ike : ∀ g ∈ gateways, g.ikeMode = .cbc ∨ g.ikeMode = .gcm)
    (esp : ∀ g ∈ gateways,
      (g.espMode = .cbc ∧ g.espHmacIntegrity = true) ∨ g.espMode = .gcm) :
    NegotiatedModesConform gateways := by
  intro g hg
  exact ⟨version g hg, ike g hg, esp g hg⟩

end TDN.Targets
