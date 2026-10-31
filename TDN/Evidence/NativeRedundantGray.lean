import TDN.Semantics.Paths

namespace TDN.Imported.native_redundant_four_levels_20261017T2240Z_scope_v2_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 37

def edges : List (Node × Node) := [(1, 3), (1, 8), (1, 20), (1, 29), (1, 32), (3, 1), (4, 5), (4, 25), (4, 29), (5, 4), (5, 9), (5, 21), (5, 33), (8, 1), (9, 5), (9, 25), (9, 29), (10, 12), (10, 17), (10, 23), (10, 30), (10, 35), (12, 10), (13, 14), (13, 27), (13, 30), (14, 13), (14, 18), (14, 24), (14, 36), (17, 10), (18, 14), (18, 27), (18, 30), (20, 1), (21, 5), (21, 25), (21, 29), (23, 10), (24, 14), (24, 27), (24, 30), (25, 4), (25, 9), (25, 21), (25, 33), (27, 13), (27, 18), (27, 24), (27, 36), (29, 1), (29, 4), (29, 9), (29, 21), (29, 33), (30, 10), (30, 13), (30, 18), (30, 24), (30, 36), (32, 1), (33, 5), (33, 25), (33, 29), (35, 10), (36, 14), (36, 27), (36, 30)]

def innerNodes : List Node := [3, 8, 12, 17, 20, 23, 32, 35]

def firewallNodes : List Node := [1, 10]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 5, 5, 5, 7, 1, 4, 4, 4, 0, 5, 5, 5, 7, 1, 4, 4, 4, 3, 3, 3, 3, 3, 3, 7, 2, 7, 2, 0, 0, 6, 6, 6, 6, 6, 6][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 3, 29, 29, 6, 7, 8, 29, 10, 11, 12, 14, 14, 15, 16, 17, 14, 19, 20, 29, 22, 23, 14, 29, 26, 14, 28, 29, 14, 31, 32, 29, 34, 35, 14][a.val]!

theorem local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by unfold edge edges firewall firewallNodes side; decide

theorem start_clear : ∀ a, a ∈ innerNodes → ¬ firewall a := by unfold innerNodes firewall firewallNodes; decide

theorem sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → side a ≠ side b := by unfold innerNodes level side; decide

theorem all_cross_level_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall side local_cut (start_clear a ha) (sides_differ a b ha hb different)

end TDN.Imported.native_redundant_four_levels_20261017T2240Z_scope_v2_gray
