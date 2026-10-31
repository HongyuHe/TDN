import Mathlib.Logic.Relation

namespace TDN.Paths

/-- Paths that have not entered a firewall. The start is checked separately. -/
def Avoiding {Node : Type} (edge : Node → Node → Prop) (firewall : Node → Prop) :=
  fun a b => edge a b ∧ ¬ firewall b

/-- A local separator labels every non-firewall edge consistently. -/
theorem avoidance_preserves_side {Node Side : Type}
    (edge : Node → Node → Prop) (firewall : Node → Prop) (side : Node → Side)
    (local : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b)
    {a b : Node} (h : Relation.ReflTransGen (Avoiding edge firewall) a b)
    (start : ¬ firewall a) : ¬ firewall b ∧ side a = side b := by
  induction h with
  | refl => exact ⟨start, rfl⟩
  | tail _ step ih => exact ⟨step.2, ih.2.trans (local _ _ step.1 ih.1 step.2)⟩

/-- Differing-side endpoints have no path avoiding the required firewall cut. -/
theorem no_firewall_free_crossing {Node Side : Type}
    (edge : Node → Node → Prop) (firewall : Node → Prop) (side : Node → Side)
    (local : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b)
    {a b : Node} (start : ¬ firewall a) (different : side a ≠ side b) :
    ¬ Relation.ReflTransGen (Avoiding edge firewall) a b := by
  intro path
  exact different (avoidance_preserves_side edge firewall side local path start).2

end TDN.Paths
