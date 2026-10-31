import TDN.Semantics.Paths

namespace TDN.Imported.shared_inline_20261017T2128Z_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 25

def edges : List (Node × Node) := [(1, 3), (1, 4), (1, 8), (1, 9), (1, 20), (1, 21), (3, 1), (4, 1), (4, 5), (5, 4), (5, 9), (5, 21), (8, 1), (9, 1), (9, 5), (10, 12), (10, 13), (10, 17), (10, 18), (10, 23), (10, 24), (12, 10), (13, 10), (13, 14), (14, 13), (14, 18), (14, 24), (17, 10), (18, 10), (18, 14), (20, 1), (21, 1), (21, 5), (23, 10), (24, 10), (24, 14)]

def innerNodes : List Node := [3, 8, 12, 17, 20, 23]

def firewallNodes : List Node := [1, 10]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 1, 1, 1, 4, 1, 2, 2, 2, 0, 1, 1, 1, 4, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 3, 9, 9, 6, 7, 8, 9, 10, 11, 12, 14, 14, 15, 16, 17, 14, 19, 20, 9, 22, 23, 14][a.val]!

theorem local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by unfold edge edges firewall firewallNodes side; decide

theorem start_clear : ∀ a, a ∈ innerNodes → ¬ firewall a := by unfold innerNodes firewall firewallNodes; decide

theorem sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → side a ≠ side b := by unfold innerNodes level side; decide

theorem all_cross_level_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall side local_cut (start_clear a ha) (sides_differ a b ha hb different)

end TDN.Imported.shared_inline_20261017T2128Z_gray
