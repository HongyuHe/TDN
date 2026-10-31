import TDN.Targets.Architecture

namespace TDN.Evidence

structure MechanismProbe where
  id : String
  expected : String
  observed : String
  transmitted : Nat
  received : Nat
  deriving DecidableEq, Repr

structure MechanismCase where
  id : String
  inner : String
  outer : String
  families : Option (Nat × Nat × Nat)
  probes : List MechanismProbe
  deriving DecidableEq, Repr

/-- Finite observed outcomes, with no universal packet-behavior conclusion. -/
def ExpectedProbeOutcomes (cases : List MechanismCase) : Prop :=
  ∀ c ∈ cases, ∀ p ∈ c.probes, p.expected = p.observed

def EachCaseHasUsefulTraffic (cases : List MechanismCase) : Prop :=
  ∀ c ∈ cases, ∃ p ∈ c.probes, p.observed = "delivered" ∧ 0 < p.received

structure MACsecChannelSetting where
  caseId : String
  device : String
  phase : String
  interface : String
  cipher : String
  protect : Bool
  encrypt : Bool
  validation : String
  replayProtect : Bool
  replayWindow : Nat
  deriving DecidableEq, Repr

/-- Only selected kernel channel flags, not MKA, key wrapping or all-port behavior. -/
def MACsecSelectedFlags (settings : List MACsecChannelSetting) : Prop :=
  ∀ setting ∈ settings,
    setting.cipher = "GCM-AES-256" ∧ setting.protect = true ∧
    setting.encrypt = true ∧ setting.validation = "strict" ∧ setting.replayProtect = true

end TDN.Evidence
