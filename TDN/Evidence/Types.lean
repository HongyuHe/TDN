import TDN.Targets.Protocol

namespace TDN.Evidence

inductive Status where
  | observed | configured | unavailable | failed | notApplicable
  deriving DecidableEq, Repr

structure DeviceFact where
  id : String
  role : String
  site : Option String
  securityLevel : Option String
  status : Status
  observationIds : List String
  deriving DecidableEq, Repr

structure ProbeFact where
  id : String
  source : String
  destination : String
  purpose : String
  observedResult : String
  status : Status
  observationIds : List String
  deriving DecidableEq, Repr

structure TunnelFact where
  id : String
  device : String
  peer : String
  layer : String
  mechanism : String
  mode : String
  status : Status
  observationIds : List String
  deriving DecidableEq, Repr

/-- A quotation of normalized observations, with no physical-world axioms. -/
structure Snapshot where
  id : String
  manifestSha256 : String
  snapshotSha256 : String
  devices : List DeviceFact
  tunnels : List TunnelFact
  probes : List ProbeFact
  deriving DecidableEq, Repr

/-- Positive observations remain bounded events, not general availability claims. -/
def HasObservedSuccess (s : Snapshot) : Prop :=
  ∃ p ∈ s.probes, p.status = .observed ∧ p.observedResult = "delivered"

/-- Nonempty provenance is independently checked by the importer. -/
def HasProvenance (s : Snapshot) : Prop :=
  (∀ d ∈ s.devices, d.status = .observed → d.observationIds ≠ []) ∧
  (∀ t ∈ s.tunnels, t.status = .observed → t.observationIds ≠ []) ∧
  (∀ p ∈ s.probes, p.status = .observed → p.observationIds ≠ [])

/-- Only the enumerated normalized IPsec tunnel modes are checked. -/
def IPsecTunnelModes (s : Snapshot) : Prop :=
  ∀ t ∈ s.tunnels, t.mechanism = "IPsec" → t.mode = "tunnel"

/-- Declared labels remain opaque evidence identifiers until source-level labels are supplied. -/
def InnerPeersSameDeclaredLevel (s : Snapshot) : Prop :=
  ∀ t ∈ s.tunnels, t.layer = "inner" →
    ∃ a ∈ s.devices, ∃ b ∈ s.devices,
      a.id = t.device ∧ b.id = t.peer ∧
      a.securityLevel ≠ none ∧ a.securityLevel = b.securityLevel

structure HardLifetimeFact where
  device : String
  stateIndex : Nat
  seconds : Nat
  deriving DecidableEq, Repr

def ESPHardLifetimesWithinBound (facts : List HardLifetimeFact) : Prop :=
  facts ≠ [] ∧ ∀ fact ∈ facts, 0 < fact.seconds ∧ fact.seconds ≤ 28800

end TDN.Evidence
