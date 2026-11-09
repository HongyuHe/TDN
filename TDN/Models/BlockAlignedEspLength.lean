import Mathlib.Data.Nat.Basic
import Mathlib.Order.Monotone.Defs
import Lean.Elab.Tactic.Omega

namespace TDN.PacketLength

def alignedWireLength (alignment trailer fixedOverhead bytes : Nat) : Nat :=
  ((bytes + trailer + (alignment - 1)) / alignment) * alignment + fixedOverhead

theorem aligned_wire_length_monotone (alignment trailer fixedOverhead : Nat) :
    Monotone (alignedWireLength alignment trailer fixedOverhead) := by
  intro small large ordered
  unfold alignedWireLength
  apply Nat.add_le_add_right
  apply Nat.mul_le_mul_right
  apply Nat.div_le_div_right
  omega

theorem all_sizes_fit_from_maximum (alignment trailer fixedOverhead maximum mtu : Nat)
    (budget : alignedWireLength alignment trailer fixedOverhead maximum ≤ mtu)
    (bytes : Nat) (bounded : bytes ≤ maximum) :
    alignedWireLength alignment trailer fixedOverhead bytes ≤ mtu :=
  (aligned_wire_length_monotone alignment trailer fixedOverhead bounded).trans budget

end TDN.PacketLength
