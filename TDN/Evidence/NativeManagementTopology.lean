import TDN.Targets.Topology

namespace TDN.Imported.native_management_20261017T2241Z_topology

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 35

def edges : List (Node × Node) := [(0, 6), (0, 11), (0, 23), (0, 28), (1, 4), (1, 9), (1, 16), (2, 3), (3, 2), (3, 4), (3, 12), (4, 1), (4, 3), (4, 5), (5, 4), (5, 6), (5, 16), (6, 0), (6, 5), (6, 16), (7, 8), (8, 7), (8, 9), (8, 14), (9, 1), (9, 8), (9, 10), (10, 9), (10, 11), (10, 16), (11, 0), (11, 10), (11, 16), (12, 3), (12, 13), (13, 12), (14, 8), (14, 15), (15, 14), (16, 1), (16, 5), (16, 6), (16, 10), (16, 11), (16, 17), (17, 16), (18, 21), (18, 26), (18, 33), (19, 20), (20, 19), (20, 21), (20, 29), (21, 18), (21, 20), (21, 22), (22, 21), (22, 23), (22, 33), (23, 0), (23, 22), (23, 33), (24, 25), (25, 24), (25, 26), (25, 31), (26, 18), (26, 25), (26, 27), (27, 26), (27, 28), (27, 33), (28, 0), (28, 27), (28, 33), (29, 20), (29, 30), (30, 29), (31, 25), (31, 32), (32, 31), (33, 18), (33, 22), (33, 23), (33, 27), (33, 28), (33, 34), (34, 33)]

def grayEdges : List (Node × Node) := [(1, 4), (1, 9), (3, 4), (4, 1), (4, 3), (4, 5), (5, 4), (8, 9), (9, 1), (9, 8), (9, 10), (10, 9), (18, 21), (18, 26), (20, 21), (21, 18), (21, 20), (21, 22), (22, 21), (25, 26), (26, 18), (26, 25), (26, 27), (27, 26)]

def insideAttachments : List (Node × Node) := [(5, 6), (10, 11), (22, 23), (27, 28)]

def outsideAttachments : List (Node × Node) := [(6, 0), (11, 0), (23, 0), (28, 0)]

def outerNodes : List Node := [5, 10, 22, 27]

def firewallNodes : List Node := [6, 11, 23, 28]

def blackNodes : List Node := [0]

def grayFirewallNodes : List Node := [1, 18]

def innerNodes : List Node := [3, 8, 20, 25]

def outerSide (node : Node) : Nat := [0, 13, 13, 13, 13, 13, 6, 13, 13, 13, 13, 11, 13, 13, 13, 13, 13, 13, 20, 20, 20, 20, 20, 23, 20, 20, 20, 20, 28, 20, 20, 20, 20, 20, 20][node.val]!

def graySide (node : Node) : Nat := [0, 1, 2, 5, 5, 5, 6, 7, 8, 8, 8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 20, 20, 23, 24, 26, 26, 26, 28, 29, 30, 31, 32, 33, 34][node.val]!

def level (node : Node) : Nat := [0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3][node.val]!

def edge (a b : Node) : Prop := (a,b) ∈ edges

def grayEdge (a b : Node) : Prop := (a,b) ∈ grayEdges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def grayFirewall (a : Node) : Prop := a ∈ grayFirewallNodes

theorem outer_local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → outerSide a = outerSide b := by unfold edge edges firewall firewallNodes outerSide; decide

theorem outer_start_clear : ∀ a, a ∈ outerNodes → ¬ firewall a := by unfold outerNodes firewall firewallNodes; decide

theorem outer_sides_differ : ∀ a b, a ∈ outerNodes → b ∈ blackNodes → outerSide a ≠ outerSide b := by unfold outerNodes blackNodes outerSide; decide

theorem all_outer_paths_cross_firewall (a b : Node) (ha : a ∈ outerNodes) (hb : b ∈ blackNodes) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall outerSide outer_local_cut (outer_start_clear a ha) (outer_sides_differ a b ha hb)

theorem inside_outside_placement : ∀ o, o ∈ outerNodes → ∃ f b, f ∈ firewallNodes ∧ b ∈ blackNodes ∧ (o,f) ∈ insideAttachments ∧ (f,b) ∈ outsideAttachments := by unfold outerNodes firewallNodes blackNodes insideAttachments outsideAttachments; decide

theorem gray_internal_connected (o : Node) (ho : o ∈ outerNodes) : ∃ f, grayFirewall f ∧ Relation.ReflTransGen grayEdge o f := by
  simp only [outerNodes, List.mem_cons, List.not_mem_nil, or_false] at ho
  rcases ho with rfl | rfl | rfl | rfl
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 5 4)).tail (by unfold grayEdge grayEdges; decide : grayEdge 4 1)⟩
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 10 9)).tail (by unfold grayEdge grayEdges; decide : grayEdge 9 1)⟩
  · exact ⟨18, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 22 21)).tail (by unfold grayEdge grayEdges; decide : grayEdge 21 18)⟩
  · exact ⟨18, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 27 26)).tail (by unfold grayEdge grayEdges; decide : grayEdge 26 18)⟩

theorem snapshot_public_internet_RG034 : Targets.msc_outer_firewall_placement true true edge (Relation.ReflTransGen grayEdge) (fun a => a ∈ outerNodes) firewall (fun a => a ∈ blackNodes) grayFirewall (fun a => a ∈ innerNodes) (fun a b => (a,b) ∈ insideAttachments) (fun a b => (a,b) ∈ outsideAttachments) (fun _ _ => False) := ⟨inside_outside_placement, all_outer_paths_cross_firewall, gray_internal_connected⟩

theorem gray_local_cut : ∀ a b, grayEdge a b → ¬ grayFirewall a → ¬ grayFirewall b → graySide a = graySide b := by unfold grayEdge grayEdges grayFirewall grayFirewallNodes graySide; decide

theorem inner_start_clear : ∀ a, a ∈ innerNodes → ¬ grayFirewall a := by unfold innerNodes grayFirewall grayFirewallNodes; decide

theorem gray_sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → graySide a ≠ graySide b := by unfold innerNodes level graySide; decide

theorem cross_level_gray_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding grayEdge grayFirewall) a b := Paths.no_firewall_free_crossing grayEdge grayFirewall graySide gray_local_cut (inner_start_clear a ha) (gray_sides_differ a b ha hb different)

def ipv6Disablement : List (Nat × Nat) := [(1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0)]

theorem all_recorded_ipv6_interfaces_disabled : ∀ setting ∈ ipv6Disablement, setting.1 = 1 ∧ setting.2 = 0 := by unfold ipv6Disablement; decide

end TDN.Imported.native_management_20261017T2241Z_topology
