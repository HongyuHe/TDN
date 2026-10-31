import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.Addressing

structure Range (Label : Type) where
  low : Nat
  high : Nat
  label : Label
  deriving DecidableEq

def Contains {Label : Type} (range : Range Label) (address : Nat) : Prop :=
  range.low ≤ address ∧ address ≤ range.high

def Owns {Label : Type} (ranges : List (Range Label)) (address : Nat) (label : Label) : Prop :=
  ∃ range ∈ ranges, Contains range address ∧ range.label = label

def Separated {Label : Type} (ranges : List (Range Label)) : Prop :=
  ∀ a ∈ ranges, ∀ b ∈ ranges, a.label ≠ b.label → a.high < b.low ∨ b.high < a.low

/-- Disjoint ranges at distinct labels make address ownership unambiguous. -/
theorem separated_ranges_unique_label {Label : Type} {ranges : List (Range Label)}
    (separated : Separated ranges) {address : Nat} {a b : Label}
    (ha : Owns ranges address a) (hb : Owns ranges address b) : a = b := by
  obtain ⟨ra, hra, hca, rfl⟩ := ha
  obtain ⟨rb, hrb, hcb, rfl⟩ := hb
  by_contra different
  have apart := separated ra hra rb hrb different
  unfold Contains at hca hcb
  omega

end TDN.Addressing
