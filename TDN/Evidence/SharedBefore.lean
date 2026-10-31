import TDN.Semantics.Paths

namespace TDN.Imported.shared_three_level_20261017T2117Z_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 25

def edges : List (Node × Node) := [(1, 4), (1, 9), (1, 21), (3, 4), (4, 1), (4, 3), (4, 5), (5, 4), (5, 9), (5, 21), (8, 9), (9, 1), (9, 5), (9, 8), (10, 13), (10, 18), (10, 24), (12, 13), (13, 10), (13, 12), (13, 14), (14, 13), (14, 18), (14, 24), (17, 18), (18, 10), (18, 14), (18, 17), (20, 21), (21, 1), (21, 5), (21, 20), (23, 24), (24, 10), (24, 14), (24, 23)]

def innerNodes : List Node := [3, 8, 12, 17, 20, 23]

def firewallNodes : List Node := [1, 10]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 1, 1, 1, 4, 1, 2, 2, 2, 0, 1, 1, 1, 4, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 20, 20, 20, 6, 7, 20, 20, 10, 11, 14, 14, 14, 15, 16, 14, 14, 19, 20, 20, 22, 14, 14][a.val]!

theorem concrete_bypass : Relation.ReflTransGen (Paths.Avoiding edge firewall) (3 : Node) 8 := ((((Relation.ReflTransGen.single (show Paths.Avoiding edge firewall (3 : Node) 4 from by unfold Paths.Avoiding edge edges firewall firewallNodes; decide)).tail (show Paths.Avoiding edge firewall (4 : Node) 5 from by unfold Paths.Avoiding edge edges firewall firewallNodes; decide)).tail (show Paths.Avoiding edge firewall (5 : Node) 9 from by unfold Paths.Avoiding edge edges firewall firewallNodes; decide)).tail (show Paths.Avoiding edge firewall (9 : Node) 8 from by unfold Paths.Avoiding edge edges firewall firewallNodes; decide))

theorem bypass_crosses_distinct_levels : (3 : Node) ∈ innerNodes ∧ (8 : Node) ∈ innerNodes ∧ level 3 ≠ level 8 ∧ ¬ firewall 3 := by unfold innerNodes level firewall firewallNodes; decide

end TDN.Imported.shared_three_level_20261017T2117Z_gray
