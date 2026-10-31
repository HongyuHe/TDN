import Mathlib.Data.List.Basic

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

structure Snapshot where
  id : String
  manifestSha256 : String
  snapshotSha256 : String
  devices : List DeviceFact
  tunnels : List TunnelFact
  probes : List ProbeFact
  deriving DecidableEq, Repr

def HasObservedSuccess (s : Snapshot) : Prop :=
  ∃ p ∈ s.probes, p.status = .observed ∧ p.observedResult = "delivered"

def HasProvenance (s : Snapshot) : Prop :=
  (∀ d ∈ s.devices, d.status = .observed → d.observationIds ≠ []) ∧
  (∀ t ∈ s.tunnels, t.status = .observed → t.observationIds ≠ []) ∧
  (∀ p ∈ s.probes, p.status = .observed → p.observationIds ≠ [])

end TDN.Evidence
