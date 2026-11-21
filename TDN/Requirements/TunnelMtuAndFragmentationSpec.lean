import Lean.Elab.Tactic.Omega
import TDN.Models.BlockAlignedEspLength

namespace TDN.Requirements

inductive SizingInterface where
  | grayFirewallOrEncryptionExternal | innerExternal | other
  deriving DecidableEq, Repr

inductive SizingFamily where
  | ipv4 | ipv6 | macsec
  deriving DecidableEq, Repr

structure PacketSizing where
  interface : Nat
  role : SizingInterface
  family : SizingFamily
  innerObjectiveSelected : Bool
  payloadLimit : Nat
  encapsulationOverheadBound : Nat
  externalMtu : Nat
  outerMtu : Nat
  blackMtu : Nat
  ipv6PmtuConfigured : Bool

  encodedSize : Nat → Nat := fun bytes => bytes + encapsulationOverheadBound

  outerEncodedSize : Nat → Nat := encodedSize

  blackEncodedSize : Nat → Nat := outerEncodedSize

end TDN.Requirements
