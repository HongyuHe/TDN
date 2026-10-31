import TDN.Semantics.Network

namespace TDN.Evidence

structure DeclaredRedNetwork where
  identity : RedNetworkIdentity
  logicalNetwork : String
  trustDomain : String
  sourceCases : List String
  deriving DecidableEq

def DifferentDomainsAtSameLevel (networks : List DeclaredRedNetwork) : Prop :=
  ∃ a ∈ networks, ∃ b ∈ networks,
    a.identity.level = b.identity.level ∧ a.logicalNetwork ≠ b.logicalNetwork ∧
    a.trustDomain ≠ b.trustDomain

def HasSourceFigureSixLevels (levels : List SecurityLevel) : Prop :=
  (∃ l ∈ levels, l.classification = "TOP_SECRET") ∧
  (∃ l ∈ levels, l.classification = "SECRET" ∧ "US_ONLY" ∈ l.dissemination) ∧
  (∃ l ∈ levels, l.classification = "SECRET" ∧ "COALITION" ∈ l.dissemination)

end TDN.Evidence
