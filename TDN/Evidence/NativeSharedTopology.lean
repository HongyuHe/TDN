import TDN.Import.Command
import TDN.Targets.Topology

namespace TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 31

tdn_data edges : List (Node × Node) from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.edges"]

tdn_data grayEdges : List (Node × Node) from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.grayEdges"]

tdn_data insideAttachments : List (Node × Node) from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.insideAttachments"]

tdn_data outsideAttachments : List (Node × Node) from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.outsideAttachments"]

tdn_data outerNodes : List Node from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.outerNodes"]

tdn_data firewallNodes : List Node from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.firewallNodes"]

tdn_data blackNodes : List Node from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.blackNodes"]

tdn_data grayFirewallNodes : List Node from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.grayFirewallNodes"]

tdn_data innerNodes : List Node from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.innerNodes"]

def outerSide (node : Node) : Nat := [0, 25, 25, 25, 25, 25, 6, 25, 25, 25, 29, 29, 29, 29, 29, 15, 29, 29, 29, 25, 25, 25, 29, 29, 29, 25, 25, 25, 29, 29, 29][node.val]!

def graySide (node : Node) : Nat := [0, 1, 2, 3, 9, 9, 6, 7, 8, 9, 10, 11, 12, 30, 30, 15, 16, 17, 30, 19, 20, 9, 22, 23, 30, 25, 26, 9, 28, 29, 30][node.val]!

def level (node : Node) : Nat := [0, 0, 4, 4, 4, 6, 1, 3, 3, 3, 0, 4, 4, 4, 6, 1, 3, 3, 3, 2, 2, 2, 2, 2, 2, 5, 5, 5, 5, 5, 5][node.val]!

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
  rcases ho with rfl | rfl
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 5 4)).tail (by unfold grayEdge grayEdges; decide : grayEdge 4 1)⟩
  · exact ⟨10, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 14 13)).tail (by unfold grayEdge grayEdges; decide : grayEdge 13 10)⟩

theorem snapshot_public_internet_RG034 : Targets.msc_outer_firewall_placement true true true edge (Relation.ReflTransGen grayEdge) (fun a => a ∈ outerNodes) firewall (fun a => a ∈ blackNodes) grayFirewall (fun a => a ∈ innerNodes) (fun a b => (a,b) ∈ insideAttachments) (fun a b => (a,b) ∈ outsideAttachments) (fun _ _ => False) := Targets.outer_firewall_placement_from_local_checks outerSide (fun _ => rfl) (by intro a b h; apply Relation.ReflTransGen.single; have checked : ∀ a b : Node, (a,b) ∈ insideAttachments ∨ (a,b) ∈ outsideAttachments ∨ False → edge a b := (by unfold insideAttachments outsideAttachments edge edges; decide); exact checked a b h) inside_outside_placement gray_internal_connected (fun _ => outer_local_cut) (fun _ => outer_start_clear) (fun _ => outer_sides_differ)

lemma gray_local_cut : ∀ a b, grayEdge a b → ¬ grayFirewall a → ¬ grayFirewall b → graySide a = graySide b := by unfold grayEdge grayEdges grayFirewall grayFirewallNodes graySide; decide

lemma inner_start_clear : ∀ a, a ∈ innerNodes → ¬ grayFirewall a := by unfold innerNodes grayFirewall grayFirewallNodes; decide

lemma gray_sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → graySide a ≠ graySide b := by unfold innerNodes level graySide; decide

theorem cross_level_gray_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding grayEdge grayFirewall) a b := Paths.no_firewall_free_crossing grayEdge grayFirewall graySide gray_local_cut (inner_start_clear a ha) (gray_sides_differ a b ha hb different)

tdn_data ipv6Disablement : List (Nat × Nat) from "../../evidence/lean/NativeSharedTopology.json" ["TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology.ipv6Disablement"]

theorem all_recorded_ipv6_interfaces_disabled : ∀ setting ∈ ipv6Disablement, setting.1 = 1 ∧ setting.2 = 0 := by unfold ipv6Disablement; decide

end TDN.Imported.native_shared_four_levels_20261017T2240Z_scope_v2_topology
