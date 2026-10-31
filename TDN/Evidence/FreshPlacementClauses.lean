import TDN.Import.Command
import TDN.Targets.PlacementClauses
import TDN.Evidence.FreshSharedTopology

namespace TDN.Imported.FreshSharedTopology
set_option maxRecDepth 100000
set_option maxHeartbeats 0
tdn_data redNodes : List Node from "../../data/evidence/FreshPlacementClauses.json" ["TDN.Imported.FreshSharedTopology.redNodes"]

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
tdn_data edges : List (Node × Node) from "../../data/evidence/FreshPlacementClauses.json" ["TDN.Imported.FreshRedundantPlacement.edges"]

tdn_data outerNodes : List Node from "../../data/evidence/FreshPlacementClauses.json" ["TDN.Imported.FreshRedundantPlacement.outerNodes"]

tdn_data firewallNodes : List Node from "../../data/evidence/FreshPlacementClauses.json" ["TDN.Imported.FreshRedundantPlacement.firewallNodes"]

tdn_data blackNodes : List Node from "../../data/evidence/FreshPlacementClauses.json" ["TDN.Imported.FreshRedundantPlacement.blackNodes"]

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
