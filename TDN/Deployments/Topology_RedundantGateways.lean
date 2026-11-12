import TDN.Import.SnapshotLoader
import TDN.Requirements.MscFirewallWaypointingTheorems

namespace TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 37

load_network_records edges : List (Node × Node) from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.edges"]

load_network_records grayEdges : List (Node × Node) from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.grayEdges"]

load_network_records insideAttachments : List (Node × Node) from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.insideAttachments"]

load_network_records outsideAttachments : List (Node × Node) from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.outsideAttachments"]

load_network_records outerNodes : List Node from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.outerNodes"]

load_network_records firewallNodes : List Node from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.firewallNodes"]

load_network_records blackNodes : List Node from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.blackNodes"]

load_network_records grayFirewallNodes : List Node from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.grayFirewallNodes"]

load_network_records innerNodes : List Node from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.innerNodes"]

def outerSide (node : Node) : Nat := [0, 3, 3, 3, 3, 3, 6, 3, 3, 3, 22, 22, 22, 22, 22, 15, 22, 22, 22, 3, 3, 3, 22, 22, 22, 3, 26, 22, 28, 3, 22, 3, 3, 3, 22, 22, 22][node.val]!

def graySide (node : Node) : Nat := [0, 1, 2, 3, 29, 29, 6, 7, 8, 29, 10, 11, 12, 14, 14, 15, 16, 17, 14, 19, 20, 29, 22, 23, 14, 29, 26, 14, 28, 29, 14, 31, 32, 29, 34, 35, 14][node.val]!

def level (node : Node) : Nat := [0, 0, 5, 5, 5, 7, 1, 4, 4, 4, 0, 5, 5, 5, 7, 1, 4, 4, 4, 3, 3, 3, 3, 3, 3, 7, 2, 7, 2, 0, 0, 6, 6, 6, 6, 6, 6][node.val]!

def edge (a b : Node) : Prop := (a,b) ∈ edges

def grayEdge (a b : Node) : Prop := (a,b) ∈ grayEdges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def grayFirewall (a : Node) : Prop := a ∈ grayFirewallNodes

lemma outer_local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → outerSide a = outerSide b := by unfold edge edges firewall firewallNodes outerSide; native_decide

lemma outer_start_clear : ∀ a, a ∈ outerNodes → ¬ firewall a := by unfold outerNodes firewall firewallNodes; native_decide

lemma outer_sides_differ : ∀ a b, a ∈ outerNodes → b ∈ blackNodes → outerSide a ≠ outerSide b := by unfold outerNodes blackNodes outerSide; native_decide

theorem outer_firewall_waypointing (a b : Node) (ha : a ∈ outerNodes) (hb : b ∈ blackNodes) : ¬ Relation.ReflTransGen (Waypointing.Avoiding edge firewall) a b := Waypointing.waypointing_of_edge_invariant edge firewall outerSide outer_local_cut (outer_start_clear a ha) (outer_sides_differ a b ha hb)

lemma inside_outside_placement : ∀ o, o ∈ outerNodes → ∃ f b, f ∈ firewallNodes ∧ b ∈ blackNodes ∧ (o,f) ∈ insideAttachments ∧ (f,b) ∈ outsideAttachments := by unfold outerNodes firewallNodes blackNodes insideAttachments outsideAttachments; native_decide

lemma gray_internal_connected (o : Node) (ho : o ∈ outerNodes) : ∃ f, grayFirewall f ∧ Relation.ReflTransGen grayEdge o f := by
  simp only [outerNodes, List.mem_cons, List.not_mem_nil, or_false] at ho
  rcases ho with rfl | rfl | rfl | rfl
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; native_decide, (((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 5 4)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 4 29)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 29 1)⟩
  · exact ⟨10, by unfold grayFirewall grayFirewallNodes; native_decide, (((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 14 13)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 13 30)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 30 10)⟩
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; native_decide, (((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 25 4)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 4 29)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 29 1)⟩
  · exact ⟨10, by unfold grayFirewall grayFirewallNodes; native_decide, (((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 27 13)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 13 30)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 30 10)⟩

theorem snapshot_public_internet_RG034 : Requirements.msc_outer_firewall_placement true true true edge (Relation.ReflTransGen grayEdge) (fun a => a ∈ outerNodes) firewall (fun a => a ∈ blackNodes) grayFirewall (fun a => a ∈ innerNodes) (fun a b => (a,b) ∈ insideAttachments) (fun a b => (a,b) ∈ outsideAttachments) (fun _ _ => False) := Requirements.outer_firewall_placement_from_local_checks outerSide (fun _ => rfl) (by intro a b h; apply Relation.ReflTransGen.single; have checked : ∀ a b : Node, (a,b) ∈ insideAttachments ∨ (a,b) ∈ outsideAttachments ∨ False → edge a b := (by unfold insideAttachments outsideAttachments edge edges; native_decide); exact checked a b h) inside_outside_placement gray_internal_connected (fun _ => outer_local_cut) (fun _ => outer_start_clear) (fun _ => outer_sides_differ)

lemma gray_local_cut : ∀ a b, grayEdge a b → ¬ grayFirewall a → ¬ grayFirewall b → graySide a = graySide b := by unfold grayEdge grayEdges grayFirewall grayFirewallNodes graySide; native_decide

lemma inner_start_clear : ∀ a, a ∈ innerNodes → ¬ grayFirewall a := by unfold innerNodes grayFirewall grayFirewallNodes; native_decide

lemma gray_sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → graySide a ≠ graySide b := by unfold innerNodes level graySide; native_decide

theorem cross_level_gray_waypointing (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Waypointing.Avoiding grayEdge grayFirewall) a b := Waypointing.waypointing_of_edge_invariant grayEdge grayFirewall graySide gray_local_cut (inner_start_clear a ha) (gray_sides_differ a b ha hb different)

load_network_records ipv6Disablement : List (Nat × Nat) from "../../data/evidence/Topology_RedundantGateways.json" ["TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology.ipv6Disablement"]

theorem all_recorded_ipv6_interfaces_disabled : ∀ setting ∈ ipv6Disablement, setting.1 = 1 ∧ setting.2 = 0 := by unfold ipv6Disablement; native_decide

end TDN.Deployments.native_redundant_four_levels_20261017T2240Z_scope_v2_topology
