import TDN.Semantics.Waypointing
import Mathlib.Data.List.Chain

namespace TDN.Targets

theorem red_egress_crosses_inner_from_attachment_cut {Node : Type}
    (edge : Node → Node → Prop) (inner : Node → Prop) (red : Node → Bool)
    (checked : ∀ a b, edge a b → ¬ inner a → ¬ inner b → red a = red b)
    {source destination : Node} (start : ¬ inner source)
    (sourceRed : red source = true) (destinationOutside : red destination = false) :
    ¬ Relation.ReflTransGen (Waypointing.Avoiding edge inner) source destination := by
  apply Waypointing.waypointing_of_edge_invariant edge inner red checked start
  rw [sourceRed, destinationOutside]
  decide

end TDN.Targets
