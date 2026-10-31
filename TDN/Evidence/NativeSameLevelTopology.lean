import TDN.Targets.Topology

namespace TDN.Imported.native_samelevel_20261017T2242Z_topology

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 19

def edges : List (Node × Node) := [(0, 6), (0, 15), (1, 4), (1, 9), (2, 3), (3, 2), (3, 4), (4, 1), (4, 3), (4, 5), (5, 4), (5, 6), (5, 9), (6, 0), (6, 5), (7, 8), (8, 7), (8, 9), (9, 1), (9, 5), (9, 8), (10, 13), (10, 18), (11, 12), (12, 11), (12, 13), (13, 10), (13, 12), (13, 14), (14, 13), (14, 15), (14, 18), (15, 0), (15, 14), (16, 17), (17, 16), (17, 18), (18, 10), (18, 14), (18, 17)]

def grayEdges : List (Node × Node) := [(1, 4), (1, 9), (3, 4), (4, 1), (4, 3), (4, 5), (5, 4), (5, 9), (8, 9), (9, 1), (9, 5), (9, 8), (10, 13), (10, 18), (12, 13), (13, 10), (13, 12), (13, 14), (14, 13), (14, 18), (17, 18), (18, 10), (18, 14), (18, 17)]

def insideAttachments : List (Node × Node) := [(5, 6), (14, 15)]

def outsideAttachments : List (Node × Node) := [(6, 0), (15, 0)]

def outerNodes : List Node := [5, 14]

def firewallNodes : List Node := [6, 15]

def blackNodes : List Node := [0]

def grayFirewallNodes : List Node := [1, 10]

def innerNodes : List Node := [3, 8, 12, 17]

def outerSide (node : Node) : Nat := [0, 1, 1, 1, 1, 1, 6, 1, 1, 1, 14, 14, 14, 14, 14, 15, 14, 14, 14][node.val]!

def graySide (node : Node) : Nat := [0, 1, 2, 8, 8, 8, 6, 7, 8, 8, 10, 11, 14, 14, 14, 15, 16, 14, 14][node.val]!

def level (node : Node) : Nat := [0, 0, 1, 1, 1, 2, 1, 1, 1, 1, 0, 1, 1, 1, 2, 1, 1, 1, 1][node.val]!

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
  rcases ho with rfl | rfl
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 5 4)).tail (by unfold grayEdge grayEdges; decide : grayEdge 4 1)⟩
  · exact ⟨10, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 14 13)).tail (by unfold grayEdge grayEdges; decide : grayEdge 13 10)⟩

theorem snapshot_public_internet_RG034 : Targets.msc_outer_firewall_placement true true edge (Relation.ReflTransGen grayEdge) (fun a => a ∈ outerNodes) firewall (fun a => a ∈ blackNodes) grayFirewall (fun a => a ∈ innerNodes) (fun a b => (a,b) ∈ insideAttachments) (fun a b => (a,b) ∈ outsideAttachments) (fun _ _ => False) := ⟨inside_outside_placement, all_outer_paths_cross_firewall, gray_internal_connected⟩

theorem gray_local_cut : ∀ a b, grayEdge a b → ¬ grayFirewall a → ¬ grayFirewall b → graySide a = graySide b := by unfold grayEdge grayEdges grayFirewall grayFirewallNodes graySide; decide

theorem inner_start_clear : ∀ a, a ∈ innerNodes → ¬ grayFirewall a := by unfold innerNodes grayFirewall grayFirewallNodes; decide

theorem gray_sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → graySide a ≠ graySide b := by unfold innerNodes level graySide; decide

theorem cross_level_gray_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding grayEdge grayFirewall) a b := Paths.no_firewall_free_crossing grayEdge grayFirewall graySide gray_local_cut (inner_start_clear a ha) (gray_sides_differ a b ha hb different)

def ipv6Disablement : List (Nat × Nat) := [(1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0)]

theorem all_recorded_ipv6_interfaces_disabled : ∀ setting ∈ ipv6Disablement, setting.1 = 1 ∧ setting.2 = 0 := by unfold ipv6Disablement; decide

end TDN.Imported.native_samelevel_20261017T2242Z_topology
