import TDN.Semantics.Paths
import Mathlib.Data.List.Chain

namespace TDN.Targets

/-- A checked branch reaches its Outer without entering any further Inner.
A shared Gray network may still admit other walks between Inners. -/
theorem independent_inner_branch_from_chain {Node : Type}
    (edge : Node → Node → Prop) (inner : Node → Prop)
    {source destination : Node} (tail : List Node)
    (chain : List.IsChain (Paths.Avoiding edge inner) (source :: tail))
    (last : (source :: tail).getLast (List.cons_ne_nil _ _) = destination) :
    Relation.ReflTransGen (Paths.Avoiding edge inner) source destination :=
  List.relationReflTransGen_of_exists_isChain_cons tail chain last

/-- An observed Red attachment separator forces every virtual egress path to
enter an Inner. Physical device approval remains a separate source obligation. -/
theorem red_egress_crosses_inner_from_attachment_cut {Node : Type}
    (edge : Node → Node → Prop) (inner : Node → Prop) (red : Node → Bool)
    (checked : ∀ a b, edge a b → ¬ inner a → ¬ inner b → red a = red b)
    {source destination : Node} (start : ¬ inner source)
    (sourceRed : red source = true) (destinationOutside : red destination = false) :
    ¬ Relation.ReflTransGen (Paths.Avoiding edge inner) source destination := by
  apply Paths.no_firewall_free_crossing edge inner red checked start
  rw [sourceRed, destinationOutside]
  decide

end TDN.Targets
