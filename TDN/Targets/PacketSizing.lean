import Lean.Elab.Tactic.Omega
import TDN.Semantics.PacketLength

namespace TDN.Targets

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

def FitsSelectedPath (sizing : PacketSizing) : Prop :=
  (sizing.family = .ipv6 → sizing.ipv6PmtuConfigured = true) ∧
  ∀ bytes, bytes ≤ sizing.payloadLimit →
    sizing.encodedSize bytes ≤ sizing.externalMtu ∧
    sizing.outerEncodedSize bytes ≤ sizing.outerMtu ∧
    (sizing.role = .innerExternal → sizing.blackEncodedSize bytes ≤ sizing.blackMtu)

def msc_packet_size_configuration (interfaces : List PacketSizing) : Prop :=
  ∀ sizing ∈ interfaces,
    sizing.role = .grayFirewallOrEncryptionExternal ∨
      (sizing.role = .innerExternal ∧ sizing.innerObjectiveSelected = true) →
    FitsSelectedPath sizing

theorem packet_sizes_fit_from_budget (sizing : PacketSizing)
    (encodingBound : ∀ bytes, sizing.encodedSize bytes ≤ bytes + sizing.encapsulationOverheadBound)
    (outerEncodingBound : ∀ bytes,
      sizing.outerEncodedSize bytes ≤ bytes + sizing.encapsulationOverheadBound)
    (blackEncodingBound : ∀ bytes,
      sizing.blackEncodedSize bytes ≤ bytes + sizing.encapsulationOverheadBound)
    (pmtu : sizing.family = .ipv6 → sizing.ipv6PmtuConfigured = true)
    (external : sizing.payloadLimit + sizing.encapsulationOverheadBound ≤ sizing.externalMtu)
    (outer : sizing.payloadLimit + sizing.encapsulationOverheadBound ≤ sizing.outerMtu)
    (black : sizing.role = .innerExternal →
      sizing.payloadLimit + sizing.encapsulationOverheadBound ≤ sizing.blackMtu) :
    FitsSelectedPath sizing := by
  refine ⟨pmtu, ?_⟩
  intro bytes size
  have encoding := encodingBound bytes
  have outerEncoding := outerEncodingBound bytes
  have blackEncoding := blackEncodingBound bytes
  constructor
  · omega
  constructor
  · omega
  intro inner
  have bound := black inner
  omega

theorem packet_sizes_fit_from_monotone_encoding (sizing : PacketSizing)
    (encoding : Monotone sizing.encodedSize)
    (outerEncoding : Monotone sizing.outerEncodedSize)
    (blackEncoding : Monotone sizing.blackEncodedSize)
    (pmtu : sizing.family = .ipv6 → sizing.ipv6PmtuConfigured = true)
    (external : sizing.encodedSize sizing.payloadLimit ≤ sizing.externalMtu)
    (outer : sizing.outerEncodedSize sizing.payloadLimit ≤ sizing.outerMtu)
    (black : sizing.role = .innerExternal →
      sizing.blackEncodedSize sizing.payloadLimit ≤ sizing.blackMtu) :
    FitsSelectedPath sizing := by
  refine ⟨pmtu, ?_⟩
  intro bytes bounded
  have maximum := encoding bounded
  exact ⟨maximum.trans external, (outerEncoding bounded).trans outer,
    fun role => (blackEncoding bounded).trans (black role)⟩

end TDN.Targets
