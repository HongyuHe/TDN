import TDN.Targets.Topology

namespace TDN.Imported.native_redundant_four_levels_20261017T2240Z_scope_v2_topology

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 37

def edges : List (Node × Node) := [(0, 6), (0, 15), (0, 26), (0, 28), (1, 3), (1, 8), (1, 20), (1, 29), (1, 32), (2, 3), (3, 1), (3, 2), (4, 5), (4, 25), (4, 29), (5, 4), (5, 6), (5, 9), (5, 21), (5, 33), (6, 0), (6, 5), (7, 8), (8, 1), (8, 7), (9, 5), (9, 25), (9, 29), (10, 12), (10, 17), (10, 23), (10, 30), (10, 35), (11, 12), (12, 10), (12, 11), (13, 14), (13, 27), (13, 30), (14, 13), (14, 15), (14, 18), (14, 24), (14, 36), (15, 0), (15, 14), (16, 17), (17, 10), (17, 16), (18, 14), (18, 27), (18, 30), (19, 20), (20, 1), (20, 19), (21, 5), (21, 25), (21, 29), (22, 23), (23, 10), (23, 22), (24, 14), (24, 27), (24, 30), (25, 4), (25, 9), (25, 21), (25, 26), (25, 33), (26, 0), (26, 25), (27, 13), (27, 18), (27, 24), (27, 28), (27, 36), (28, 0), (28, 27), (29, 1), (29, 4), (29, 9), (29, 21), (29, 33), (30, 10), (30, 13), (30, 18), (30, 24), (30, 36), (31, 32), (32, 1), (32, 31), (33, 5), (33, 25), (33, 29), (34, 35), (35, 10), (35, 34), (36, 14), (36, 27), (36, 30)]

def grayEdges : List (Node × Node) := [(1, 3), (1, 8), (1, 20), (1, 29), (1, 32), (3, 1), (4, 5), (4, 25), (4, 29), (5, 4), (5, 9), (5, 21), (5, 33), (8, 1), (9, 5), (9, 25), (9, 29), (10, 12), (10, 17), (10, 23), (10, 30), (10, 35), (12, 10), (13, 14), (13, 27), (13, 30), (14, 13), (14, 18), (14, 24), (14, 36), (17, 10), (18, 14), (18, 27), (18, 30), (20, 1), (21, 5), (21, 25), (21, 29), (23, 10), (24, 14), (24, 27), (24, 30), (25, 4), (25, 9), (25, 21), (25, 33), (27, 13), (27, 18), (27, 24), (27, 36), (29, 1), (29, 4), (29, 9), (29, 21), (29, 33), (30, 10), (30, 13), (30, 18), (30, 24), (30, 36), (32, 1), (33, 5), (33, 25), (33, 29), (35, 10), (36, 14), (36, 27), (36, 30)]

def insideAttachments : List (Node × Node) := [(5, 6), (14, 15), (25, 26), (27, 28)]

def outsideAttachments : List (Node × Node) := [(6, 0), (15, 0), (26, 0), (28, 0)]

def outerNodes : List Node := [5, 14, 25, 27]

def firewallNodes : List Node := [6, 15, 26, 28]

def blackNodes : List Node := [0]

def grayFirewallNodes : List Node := [1, 10]

def innerNodes : List Node := [3, 8, 12, 17, 20, 23, 32, 35]

def outerSide (node : Node) : Nat := [0, 3, 3, 3, 3, 3, 6, 3, 3, 3, 22, 22, 22, 22, 22, 15, 22, 22, 22, 3, 3, 3, 22, 22, 22, 3, 26, 22, 28, 3, 22, 3, 3, 3, 22, 22, 22][node.val]!

def graySide (node : Node) : Nat := [0, 1, 2, 3, 29, 29, 6, 7, 8, 29, 10, 11, 12, 14, 14, 15, 16, 17, 14, 19, 20, 29, 22, 23, 14, 29, 26, 14, 28, 29, 14, 31, 32, 29, 34, 35, 14][node.val]!

def level (node : Node) : Nat := [0, 0, 5, 5, 5, 7, 1, 4, 4, 4, 0, 5, 5, 5, 7, 1, 4, 4, 4, 3, 3, 3, 3, 3, 3, 7, 2, 7, 2, 0, 0, 6, 6, 6, 6, 6, 6][node.val]!

def edge (a b : Node) : Prop := (a,b) ∈ edges

def grayEdge (a b : Node) : Prop := (a,b) ∈ grayEdges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def grayFirewall (a : Node) : Prop := a ∈ grayFirewallNodes

lemma outer_local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → outerSide a = outerSide b := by unfold edge edges firewall firewallNodes outerSide; decide

lemma outer_start_clear : ∀ a, a ∈ outerNodes → ¬ firewall a := by unfold outerNodes firewall firewallNodes; decide

lemma outer_sides_differ : ∀ a b, a ∈ outerNodes → b ∈ blackNodes → outerSide a ≠ outerSide b := by unfold outerNodes blackNodes outerSide; decide

theorem all_outer_paths_cross_firewall (a b : Node) (ha : a ∈ outerNodes) (hb : b ∈ blackNodes) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall outerSide outer_local_cut (outer_start_clear a ha) (outer_sides_differ a b ha hb)

lemma inside_outside_placement : ∀ o, o ∈ outerNodes → ∃ f b, f ∈ firewallNodes ∧ b ∈ blackNodes ∧ (o,f) ∈ insideAttachments ∧ (f,b) ∈ outsideAttachments := by unfold outerNodes firewallNodes blackNodes insideAttachments outsideAttachments; decide

lemma gray_internal_connected (o : Node) (ho : o ∈ outerNodes) : ∃ f, grayFirewall f ∧ Relation.ReflTransGen grayEdge o f := by
  simp only [outerNodes, List.mem_cons, List.not_mem_nil, or_false] at ho
  rcases ho with rfl | rfl | rfl | rfl
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; decide, (((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 5 4)).tail (by unfold grayEdge grayEdges; decide : grayEdge 4 29)).tail (by unfold grayEdge grayEdges; decide : grayEdge 29 1)⟩
  · exact ⟨10, by unfold grayFirewall grayFirewallNodes; decide, (((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 14 13)).tail (by unfold grayEdge grayEdges; decide : grayEdge 13 30)).tail (by unfold grayEdge grayEdges; decide : grayEdge 30 10)⟩
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; decide, (((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 25 4)).tail (by unfold grayEdge grayEdges; decide : grayEdge 4 29)).tail (by unfold grayEdge grayEdges; decide : grayEdge 29 1)⟩
  · exact ⟨10, by unfold grayFirewall grayFirewallNodes; decide, (((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 27 13)).tail (by unfold grayEdge grayEdges; decide : grayEdge 13 30)).tail (by unfold grayEdge grayEdges; decide : grayEdge 30 10)⟩

theorem snapshot_public_internet_RG034 : Targets.msc_outer_firewall_placement true true true edge (Relation.ReflTransGen grayEdge) (fun a => a ∈ outerNodes) firewall (fun a => a ∈ blackNodes) grayFirewall (fun a => a ∈ innerNodes) (fun a b => (a,b) ∈ insideAttachments) (fun a b => (a,b) ∈ outsideAttachments) (fun _ _ => False) := Targets.outer_firewall_placement_from_local_checks outerSide (fun _ => rfl) (by intro a b h; apply Relation.ReflTransGen.single; have checked : ∀ a b : Node, (a,b) ∈ insideAttachments ∨ (a,b) ∈ outsideAttachments ∨ False → edge a b := (by unfold insideAttachments outsideAttachments edge edges; decide); exact checked a b h) inside_outside_placement gray_internal_connected (fun _ => outer_local_cut) (fun _ => outer_start_clear) (fun _ => outer_sides_differ)

lemma gray_local_cut : ∀ a b, grayEdge a b → ¬ grayFirewall a → ¬ grayFirewall b → graySide a = graySide b := by unfold grayEdge grayEdges grayFirewall grayFirewallNodes graySide; decide

lemma inner_start_clear : ∀ a, a ∈ innerNodes → ¬ grayFirewall a := by unfold innerNodes grayFirewall grayFirewallNodes; decide

lemma gray_sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → graySide a ≠ graySide b := by unfold innerNodes level graySide; decide

theorem cross_level_gray_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding grayEdge grayFirewall) a b := Paths.no_firewall_free_crossing grayEdge grayFirewall graySide gray_local_cut (inner_start_clear a ha) (gray_sides_differ a b ha hb different)

def ipv6Disablement : List (Nat × Nat) := [(1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0)]

theorem all_recorded_ipv6_interfaces_disabled : ∀ setting ∈ ipv6Disablement, setting.1 = 1 ∧ setting.2 = 0 := by unfold ipv6Disablement; decide

end TDN.Imported.native_redundant_four_levels_20261017T2240Z_scope_v2_topology
