import TDN.Semantics.Paths

namespace TDN.Imported.same_level_coherent_20261017T2149Z_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 19

def edges : List (Node × Node) := [(1, 4), (1, 9), (3, 4), (4, 1), (4, 3), (4, 5), (5, 4), (5, 9), (8, 9), (9, 1), (9, 5), (9, 8), (10, 13), (10, 18), (12, 13), (13, 10), (13, 12), (13, 14), (14, 13), (14, 18), (17, 18), (18, 10), (18, 14), (18, 17)]

def innerNodes : List Node := [3, 8, 12, 17]

def firewallNodes : List Node := [1, 10]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 1, 1, 1, 2, 1, 1, 1, 1, 0, 1, 1, 1, 2, 1, 1, 1, 1][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 8, 8, 8, 6, 7, 8, 8, 10, 11, 14, 14, 14, 15, 16, 14, 14][a.val]!

end TDN.Imported.same_level_coherent_20261017T2149Z_gray
