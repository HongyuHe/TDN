import Mathlib.Logic.Relation

namespace TDN.Paths

def Avoiding {Node : Type} (edge : Node → Node → Prop) (firewall : Node → Prop) :=
  fun a b => edge a b ∧ ¬ firewall b

theorem avoidance_preserves_side {Node Side : Type}
    (edge : Node → Node → Prop) (firewall : Node → Prop) (side : Node → Side)
    (localRule : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b)
    {a b : Node} (h : Relation.ReflTransGen (Avoiding edge firewall) a b)
    (start : ¬ firewall a) : ¬ firewall b ∧ side a = side b := by
  induction h with
  | refl => exact ⟨start, rfl⟩
  | tail _ step ih => exact ⟨step.2, ih.2.trans (localRule _ _ step.1 ih.1 step.2)⟩

theorem no_firewall_free_crossing {Node Side : Type}
    (edge : Node → Node → Prop) (firewall : Node → Prop) (side : Node → Side)
    (localRule : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b)
    {a b : Node} (start : ¬ firewall a) (different : side a ≠ side b) :
    ¬ Relation.ReflTransGen (Avoiding edge firewall) a b := by
  intro path
  exact different (avoidance_preserves_side edge firewall side localRule path start).2

lemma path_avoids_absent_firewalls {Node : Type} (edge : Node → Node → Prop)
    (firewall : Node → Prop) (clear : ∀ node, ¬ firewall node) {a b : Node}
    (path : Relation.ReflTransGen edge a b) :
    Relation.ReflTransGen (Avoiding edge firewall) a b := by
  induction path with
  | refl => exact .refl
  | tail _ step ih => exact ih.tail ⟨step, clear _⟩

end TDN.Paths
