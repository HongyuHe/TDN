import TDN.Targets.PlacementClauses
import TDN.Evidence.FreshSharedTopology

namespace TDN.Imported.FreshSharedTopology
set_option maxRecDepth 100000
set_option maxHeartbeats 0
def independentBranches : List (Node × Node × List Node) := [(3, 5, [1, 4, 5]), (8, 5, [1, 4, 5]), (12, 14, [10, 13, 14]), (17, 14, [10, 13, 14]), (20, 5, [1, 4, 5]), (23, 14, [10, 13, 14]), (26, 5, [1, 4, 5]), (29, 14, [10, 13, 14])]

lemma branch_checks : ∀ branch ∈ independentBranches,
    inner branch.1 ∧ outer branch.2.1 ∧
    List.IsChain (Paths.Avoiding grayEdge inner) (branch.1 :: branch.2.2) ∧
    (branch.1 :: branch.2.2).getLast (List.cons_ne_nil _ _) = branch.2.1 := by
  unfold independentBranches inner innerNodes outer outerNodes Paths.Avoiding grayEdge grayEdges
  decide

lemma branch_inventory_complete : ∀ node ∈ innerNodes,
    ∃ branch ∈ independentBranches, branch.1 = node := by
  unfold innerNodes independentBranches
  decide

theorem every_inner_has_an_independent_outer_branch (node : Node) (member : node ∈ innerNodes) :
    ∃ destination, outer destination ∧
      Relation.ReflTransGen (Paths.Avoiding grayEdge inner) node destination := by
  obtain ⟨branch, present, same⟩ := branch_inventory_complete node member
  obtain ⟨_, destination, chain, last⟩ := branch_checks branch present
  refine ⟨branch.2.1, destination, ?_⟩
  rw [← same]
  exact Targets.independent_inner_branch_from_chain grayEdge inner branch.2.2 chain last

def redNodes : List Node := [2, 7, 11, 16, 19, 22, 25, 28]
def isRed (node : Node) : Bool := node ∈ redNodes
lemma red_attachment_cut : ∀ a b, edge a b → ¬ inner a → ¬ inner b → isRed a = isRed b := by
  unfold edge edges inner innerNodes isRed redNodes
  decide
lemma red_start_clear : ∀ node ∈ redNodes, ¬ inner node := by
  unfold redNodes inner innerNodes
  decide
lemma actual_red_attachment_nonempty : redNodes ≠ [] ∧
    ∀ node ∈ redNodes, ∃ gateway, inner gateway ∧ edge node gateway := by
  unfold redNodes inner innerNodes edge edges
  decide

theorem every_virtual_red_egress_crosses_inner (source destination : Node)
    (start : source ∈ redNodes) (outside : isRed destination = false) :
    ¬ Relation.ReflTransGen (Paths.Avoiding edge inner) source destination :=
  Targets.red_egress_crosses_inner_from_attachment_cut edge inner isRed red_attachment_cut
    (red_start_clear source start) (by simpa [isRed] using start) outside

end TDN.Imported.FreshSharedTopology

namespace TDN.Imported.FreshRedundantPlacement
set_option maxRecDepth 100000
set_option maxHeartbeats 0
abbrev Node := Fin 37
def edges : List (Node × Node) := [(0, 6), (0, 15), (0, 26), (0, 28), (1, 3), (1, 8), (1, 20), (1, 29), (1, 32), (2, 3), (3, 1), (3, 2), (4, 5), (4, 25), (4, 29), (5, 4), (5, 6), (5, 9), (5, 21), (5, 33), (6, 0), (6, 5), (7, 8), (8, 1), (8, 7), (9, 5), (9, 25), (9, 29), (10, 12), (10, 17), (10, 23), (10, 30), (10, 35), (11, 12), (12, 10), (12, 11), (13, 14), (13, 27), (13, 30), (14, 13), (14, 15), (14, 18), (14, 24), (14, 36), (15, 0), (15, 14), (16, 17), (17, 10), (17, 16), (18, 14), (18, 27), (18, 30), (19, 20), (20, 1), (20, 19), (21, 5), (21, 25), (21, 29), (22, 23), (23, 10), (23, 22), (24, 14), (24, 27), (24, 30), (25, 4), (25, 9), (25, 21), (25, 26), (25, 33), (26, 0), (26, 25), (27, 13), (27, 18), (27, 24), (27, 28), (27, 36), (28, 0), (28, 27), (29, 1), (29, 4), (29, 9), (29, 21), (29, 33), (30, 10), (30, 13), (30, 18), (30, 24), (30, 36), (31, 32), (32, 1), (32, 31), (33, 5), (33, 25), (33, 29), (34, 35), (35, 10), (35, 34), (36, 14), (36, 27), (36, 30)]
def outerNodes : List Node := [5, 14, 25, 27]
def firewallNodes : List Node := [6, 15, 26, 28]
def blackNodes : List Node := [0]
def side (node : Node) : Nat := [0, 3, 3, 3, 3, 3, 6, 3, 3, 3, 22, 22, 22, 22, 22, 15, 22, 22, 22, 3, 3, 3, 22, 22, 22, 3, 26, 22, 28, 3, 22, 3, 3, 3, 22, 22, 22][node.val]!
def edge (a b : Node) : Prop := (a,b) ∈ edges
def firewall (node : Node) : Prop := node ∈ firewallNodes
lemma actual_redundant_inventory : outerNodes.length = 4 := by decide
lemma local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by
  unfold edge edges firewall firewallNodes side
  decide
lemma starts_clear : ∀ node ∈ outerNodes, ¬ firewall node := by
  unfold outerNodes firewall firewallNodes
  decide
lemma sides_differ : ∀ source ∈ outerNodes, ∀ destination ∈ blackNodes,
    side source ≠ side destination := by
  unfold outerNodes blackNodes side
  decide
lemma actual_firewall_connections : ∀ source ∈ outerNodes, ∃ f ∈ firewallNodes,
    ∃ destination ∈ blackNodes, edge source f ∧ edge f destination := by
  unfold outerNodes firewallNodes blackNodes edge edges
  decide
theorem redundant_outers_preserve_required_firewall_cut (source destination : Node)
    (start : source ∈ outerNodes) (finish : destination ∈ blackNodes) :
    ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) source destination :=
  Paths.no_firewall_free_crossing edge firewall side local_cut
    (starts_clear source start) (sides_differ source start destination finish)
end TDN.Imported.FreshRedundantPlacement
