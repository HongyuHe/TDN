import TDN.Targets.PacketSizing

namespace TDN.Targets.NestedSizing

inductive Stage where
  | red | gray | black
  deriving DecidableEq, Repr

structure InterfaceLimit where
  device : String
  iface : String
  stage : Stage
  mtu : Nat
  deriving DecidableEq, Repr

def lengthAt (inner outer : Nat → Nat) (stage : Stage) (bytes : Nat) : Nat :=
  match stage with
  | .red => bytes
  | .gray => inner bytes
  | .black => outer (inner bytes)

lemma length_at_monotone (inner outer : Nat → Nat)
    (innerMonotone : Monotone inner) (outerMonotone : Monotone outer)
    (stage : Stage) : Monotone (lengthAt inner outer stage) := by
  cases stage with
  | red => exact fun _ _ bounded => bounded
  | gray => exact innerMonotone
  | black => exact fun _ _ bounded => outerMonotone (innerMonotone bounded)

theorem all_sizes_fit_each_interface (inner outer : Nat → Nat)
    (innerMonotone : Monotone inner) (outerMonotone : Monotone outer)
    (interfaces : List InterfaceLimit) (maximum : Nat)
    (checks : ∀ entry ∈ interfaces,
      lengthAt inner outer entry.stage maximum ≤ entry.mtu) :
    ∀ bytes, bytes ≤ maximum → ∀ entry ∈ interfaces,
      lengthAt inner outer entry.stage bytes ≤ entry.mtu := by
  intro bytes bounded entry present
  exact (length_at_monotone inner outer innerMonotone outerMonotone
    entry.stage bounded).trans (checks entry present)

end TDN.Targets.NestedSizing
