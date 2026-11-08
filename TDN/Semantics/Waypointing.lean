import Mathlib.Logic.Relation

namespace TDN.Waypointing

def Avoiding {Node : Type} (edge : Node → Node → Prop) (waypoint : Node → Prop) :=
  fun a b => edge a b ∧ ¬ waypoint b

theorem waypoint_free_path_preserves_region {Node Side : Type}
    (edge : Node → Node → Prop) (waypoint : Node → Prop) (region : Node → Side)
    (localRule : ∀ a b, edge a b → ¬ waypoint a → ¬ waypoint b → region a = region b)
    {a b : Node} (h : Relation.ReflTransGen (Avoiding edge waypoint) a b)
    (start : ¬ waypoint a) : ¬ waypoint b ∧ region a = region b := by
  induction h with
  | refl => exact ⟨start, rfl⟩
  | tail _ step ih => exact ⟨step.2, ih.2.trans (localRule _ _ step.1 ih.1 step.2)⟩

theorem waypointing_of_edge_invariant {Node Side : Type}
    (edge : Node → Node → Prop) (waypoint : Node → Prop) (region : Node → Side)
    (localRule : ∀ a b, edge a b → ¬ waypoint a → ¬ waypoint b → region a = region b)
    {a b : Node} (start : ¬ waypoint a) (different : region a ≠ region b) :
    ¬ Relation.ReflTransGen (Avoiding edge waypoint) a b := by
  intro path
  exact different (waypoint_free_path_preserves_region edge waypoint region localRule path start).2

lemma path_avoids_absent_waypoints {Node : Type} (edge : Node → Node → Prop)
    (waypoint : Node → Prop) (clear : ∀ node, ¬ waypoint node) {a b : Node}
    (path : Relation.ReflTransGen edge a b) :
    Relation.ReflTransGen (Avoiding edge waypoint) a b := by
  induction path with
  | refl => exact .refl
  | tail _ step ih => exact ih.tail ⟨step, clear _⟩

end TDN.Waypointing
