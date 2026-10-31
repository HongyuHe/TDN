import TDN.Import.Command
import TDN.Semantics.Paths

namespace TDN.Imported.shared_three_level_20261017T2117Z_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 25

tdn_data edges : List (Node × Node) from "../../evidence/lean/SharedBefore.json" ["TDN.Imported.shared_three_level_20261017T2117Z_gray.edges"]

tdn_data innerNodes : List Node from "../../evidence/lean/SharedBefore.json" ["TDN.Imported.shared_three_level_20261017T2117Z_gray.innerNodes"]

tdn_data firewallNodes : List Node from "../../evidence/lean/SharedBefore.json" ["TDN.Imported.shared_three_level_20261017T2117Z_gray.firewallNodes"]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 1, 1, 1, 4, 1, 2, 2, 2, 0, 1, 1, 1, 4, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 20, 20, 20, 6, 7, 20, 20, 10, 11, 14, 14, 14, 15, 16, 14, 14, 19, 20, 20, 22, 14, 14][a.val]!

theorem concrete_bypass : Relation.ReflTransGen (Paths.Avoiding edge firewall) (3 : Node) 8 := ((((Relation.ReflTransGen.single (show Paths.Avoiding edge firewall (3 : Node) 4 from by unfold Paths.Avoiding edge edges firewall firewallNodes; decide)).tail (show Paths.Avoiding edge firewall (4 : Node) 5 from by unfold Paths.Avoiding edge edges firewall firewallNodes; decide)).tail (show Paths.Avoiding edge firewall (5 : Node) 9 from by unfold Paths.Avoiding edge edges firewall firewallNodes; decide)).tail (show Paths.Avoiding edge firewall (9 : Node) 8 from by unfold Paths.Avoiding edge edges firewall firewallNodes; decide))

theorem bypass_crosses_distinct_levels : (3 : Node) ∈ innerNodes ∧ (8 : Node) ∈ innerNodes ∧ level 3 ≠ level 8 ∧ ¬ firewall 3 := by unfold innerNodes level firewall firewallNodes; decide

end TDN.Imported.shared_three_level_20261017T2117Z_gray
