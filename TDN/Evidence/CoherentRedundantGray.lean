import TDN.Semantics.Paths

namespace TDN.Imported.redundant_router_coherent_20261017T2149Z_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 31

def edges : List (Node × Node) := [(1, 3), (1, 8), (1, 20), (1, 29), (3, 1), (4, 5), (4, 25), (4, 29), (5, 4), (5, 9), (5, 21), (8, 1), (9, 5), (9, 25), (9, 29), (10, 12), (10, 17), (10, 23), (10, 30), (12, 10), (13, 14), (13, 27), (13, 30), (14, 13), (14, 18), (14, 24), (17, 10), (18, 14), (18, 27), (18, 30), (20, 1), (21, 5), (21, 25), (21, 29), (23, 10), (24, 14), (24, 27), (24, 30), (25, 4), (25, 9), (25, 21), (27, 13), (27, 18), (27, 24), (29, 1), (29, 4), (29, 9), (29, 21), (30, 10), (30, 13), (30, 18), (30, 24)]

def innerNodes : List Node := [3, 8, 12, 17, 20, 23]

def firewallNodes : List Node := [1, 10]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 1, 1, 1, 4, 1, 2, 2, 2, 0, 1, 1, 1, 4, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3, 4, 2, 4, 2, 0, 0][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 3, 29, 29, 6, 7, 8, 29, 10, 11, 12, 14, 14, 15, 16, 17, 14, 19, 20, 29, 22, 23, 14, 29, 26, 14, 28, 29, 14][a.val]!

theorem local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by unfold edge edges firewall firewallNodes side; decide

theorem start_clear : ∀ a, a ∈ innerNodes → ¬ firewall a := by unfold innerNodes firewall firewallNodes; decide

theorem sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → side a ≠ side b := by unfold innerNodes level side; decide

theorem all_cross_level_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall side local_cut (start_clear a ha) (sides_differ a b ha hb different)

end TDN.Imported.redundant_router_coherent_20261017T2149Z_gray
