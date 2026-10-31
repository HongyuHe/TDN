import TDN.Semantics.Temporal
import TDN.Semantics.Admission
import TDN.Semantics.LinkProtection

namespace TDN.Targets

inductive IKEEventKind where
  | peerReauthentication | ikeRekey
  deriving DecidableEq, Repr

/-- Order is a causal sequence position; timeSeconds is a physical UTC timestamp.
Association identifies the peer pair's session. Generation and episode identify the
particular replacement being authenticated, excluding unrelated or stale authentications. -/
structure IKEEvent where
  device : String
  peer : String
  association : String
  generation : Nat
  episode : Nat
  kind : IKEEventKind
  order : Nat
  timeSeconds : Nat
  localAuthenticatedPeer : Bool
  peerAuthenticatedLocal : Bool
  deriving DecidableEq, Repr

def MatchingReauthentication (authentication rekey : IKEEvent) : Prop :=
  authentication.kind = .peerReauthentication ∧
  authentication.device = rekey.device ∧ authentication.peer = rekey.peer ∧
  authentication.association = rekey.association ∧ authentication.generation = rekey.generation ∧
  authentication.episode = rekey.episode ∧ authentication.order < rekey.order ∧
  authentication.localAuthenticatedPeer = true ∧ authentication.peerAuthenticatedLocal = true

/-- MSC-VG-16 requires matching peer reauthentication for the actual replacement episode. -/
def RekeyDiscipline (events : List IKEEvent) : Prop :=
  ∀ event ∈ events, event.kind = .ikeRekey →
    ∃ authentication ∈ events, MatchingReauthentication authentication event

theorem rekey_discipline_from_admitted_events (events actions : List IKEEvent)
    (run : (Admission.lts (fun event : IKEEvent => event.kind = .ikeRekey)
      MatchingReauthentication).MTr [] actions events) : RekeyDiscipline events :=
  Admission.all_admitted_events_have_prerequisites _ _ run

def SALifetimeBounds (ikeSeconds espSeconds : Nat) : Prop :=
  0 < ikeSeconds ∧ ikeSeconds ≤ 86400 ∧ 0 < espSeconds ∧ espSeconds ≤ 28800


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

/-- RG-023. These are positive effective SA lifetimes, not rekey scheduling intervals.
A configured zero meaning disabled is never imported as a zero-second lifetime.
Event coverage and configuration inventory are explicit external obligations. -/
def msc_vpn_sa_lifetimes_and_reauthentication
    (gateways : List VPNLifetimes) (events : List IKEEvent) : Prop :=
  (∀ g ∈ gateways, SALifetimeBounds g.ikeLifetimeSeconds g.espLifetimeSeconds) ∧
  Targets.RekeyDiscipline events

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

/-- MD1 and MD2 are independent configuration checks on the same complete device inventory. -/
theorem macsec_algorithms_from_local_checks (devices : List MACsecAlgorithms)
    (distribution : ∀ d ∈ devices,
      d.keyWrapAlgorithm = "AES Key Wrap" ∧ d.keyWrapBits = 256)
    (protection : ∀ d ∈ devices,
      d.protectionAlgorithm = "AES GCM" ∧ d.protectionBits = 256) :
    msc_macsec_encryption_and_key_wrap devices := by
  intro device member
  exact ⟨(distribution device member).1, (distribution device member).2,
    protection device member⟩

structure MACsecProtection where
  device : Nat
  dataDelayProtection : Bool
  lifetimeMilliseconds : Nat
  /-- INT-028: normal Hello timeout limit, distinct from an active bounded interval. -/
  helloMilliseconds : Nat
  activeHelloMilliseconds : Nat
  replayWindow : Nat
  feasibleReplayWindow : Nat → Prop
  confidentialityOffset : Nat
  mustSecure : Bool
  dataPort : LinkProtection.Config

/-- RG-028. Replay-window feasibility and observed event coverage are not invented. -/
def msc_macsec_protection_parameters (devices : List MACsecProtection) : Prop :=
  ∀ d ∈ devices,
    d.dataDelayProtection = true ∧
    d.lifetimeMilliseconds = 6000 ∧ d.helloMilliseconds = 2000 ∧
    0 < d.activeHelloMilliseconds ∧ d.activeHelloMilliseconds ≤ d.helloMilliseconds ∧
    (d.replayWindow = 2 ∨
      (d.feasibleReplayWindow d.replayWindow ∧
        ∀ w, d.feasibleReplayWindow w → d.replayWindow ≤ w)) ∧
    (∀ association body wire,
      LinkProtection.transmit d.dataPort association (body : Nat) = some wire →
      LinkProtection.FullyEncrypted wire) ∧
    d.confidentialityOffset = 0 ∧ d.mustSecure = true

/-- Configuration and local transmit semantics establish the universal data-port clause.
The delay-protection flag denotes enabled behavior under the declared implementation contract;
the separate SequenceFreshness theorem states its timing and counter premises. -/
theorem macsec_protection_from_local_checks (devices : List MACsecProtection)
    (timers : ∀ d ∈ devices, d.dataDelayProtection = true ∧
      d.lifetimeMilliseconds = 6000 ∧ d.helloMilliseconds = 2000 ∧
      0 < d.activeHelloMilliseconds ∧ d.activeHelloMilliseconds ≤ d.helloMilliseconds)
    (replay : ∀ d ∈ devices, d.replayWindow = 2 ∨
      (d.feasibleReplayWindow d.replayWindow ∧
        ∀ w, d.feasibleReplayWindow w → d.replayWindow ≤ w))
    (dataSettings : ∀ d ∈ devices, d.dataPort.protectFrames = true ∧
      d.dataPort.encryptFrames = true ∧ d.dataPort.confidentialityOffset = 0)
    (otherSettings : ∀ d ∈ devices, d.confidentialityOffset = 0 ∧ d.mustSecure = true) :
    msc_macsec_protection_parameters devices := by
  intro d member
  obtain ⟨delay, lifetime, normal, positive, active⟩ := timers d member
  obtain ⟨protect, encrypt, zero⟩ := dataSettings d member
  refine ⟨delay, lifetime, normal, positive, active, replay d member, ?_, otherSettings d member⟩
  intro association body wire emitted
  exact LinkProtection.every_emitted_frame_is_encrypted d.dataPort protect encrypt zero
    association body wire emitted

/-- A complete finite configuration check proves precisely the configuration clause. -/
theorem vpn_modes_of_checked_inventory (gateways : List VPNConfig)
    (version : ∀ g ∈ gateways, g.ikeVersion = 2)
    (ike : ∀ g ∈ gateways, g.ikeMode = .cbc ∨ g.ikeMode = .gcm)
    (esp : ∀ g ∈ gateways,
      (g.espMode = .cbc ∧ g.espHmacIntegrity = true) ∨ g.espMode = .gcm) :
    NegotiatedModesConform gateways := by
  intro g hg
  exact ⟨version g hg, ike g hg, esp g hg⟩


/-- Local proposal checks quantify every loaded alternative, so a future selected
proposal cannot escape the permitted IKE version and independent IKE/ESP choices. -/
theorem vpn_mode_policies_from_complete_local_checks (gateways : List VPNModePolicy)
    (versions : ∀ g ∈ gateways, g.ikeVersions ≠ [] ∧ ∀ version ∈ g.ikeVersions, version = 2)
    (ike : ∀ g ∈ gateways, g.ikeModes ≠ [] ∧ ∀ mode ∈ g.ikeModes, mode = .cbc ∨ mode = .gcm)
    (esp : ∀ g ∈ gateways, g.espProposals ≠ [] ∧ ∀ proposal ∈ g.espProposals,
      (proposal.mode = .cbc ∧ proposal.hmacIntegrity = true) ∨ proposal.mode = .gcm) :
    msc_ike_version_and_encryption_modes gateways := by
  intro gateway member
  exact ⟨(versions gateway member).1, (versions gateway member).2,
    (ike gateway member).1, (ike gateway member).2, esp gateway member⟩

end TDN.Targets
