import TDN.Semantics.Paths

namespace TDN.Imported.shared_four_levels_coherent_20261017T2208Z_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 31

def edges : List (Node × Node) := [(1, 3), (1, 4), (1, 8), (1, 9), (1, 20), (1, 21), (1, 26), (1, 27), (3, 1), (4, 1), (4, 5), (5, 4), (5, 9), (5, 21), (5, 27), (8, 1), (9, 1), (9, 5), (10, 12), (10, 13), (10, 17), (10, 18), (10, 23), (10, 24), (10, 29), (10, 30), (12, 10), (13, 10), (13, 14), (14, 13), (14, 18), (14, 24), (14, 30), (17, 10), (18, 10), (18, 14), (20, 1), (21, 1), (21, 5), (23, 10), (24, 10), (24, 14), (26, 1), (27, 1), (27, 5), (29, 10), (30, 10), (30, 14)]

def innerNodes : List Node := [3, 8, 12, 17, 20, 23, 26, 29]

def firewallNodes : List Node := [1, 10]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 4, 4, 4, 6, 1, 3, 3, 3, 0, 4, 4, 4, 6, 1, 3, 3, 3, 2, 2, 2, 2, 2, 2, 5, 5, 5, 5, 5, 5][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 3, 9, 9, 6, 7, 8, 9, 10, 11, 12, 30, 30, 15, 16, 17, 30, 19, 20, 9, 22, 23, 30, 25, 26, 9, 28, 29, 30][a.val]!

lemma local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by unfold edge edges firewall firewallNodes side; decide

lemma start_clear : ∀ a, a ∈ innerNodes → ¬ firewall a := by unfold innerNodes firewall firewallNodes; decide

lemma sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → side a ≠ side b := by unfold innerNodes level side; decide

theorem all_cross_level_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall side local_cut (start_clear a ha) (sides_differ a b ha hb different)

end TDN.Imported.shared_four_levels_coherent_20261017T2208Z_gray
