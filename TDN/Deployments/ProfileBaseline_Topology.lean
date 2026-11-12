import TDN.Import.SnapshotLoader
import TDN.Requirements.MscFirewallWaypointingTheorems

namespace TDN.Deployments.ProfileBaseline_Topology

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 23

load_network_records edges : List (Node × Node) from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.edges"]

load_network_records grayEdges : List (Node × Node) from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.grayEdges"]

load_network_records insideAttachments : List (Node × Node) from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.insideAttachments"]

load_network_records outsideAttachments : List (Node × Node) from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.outsideAttachments"]

load_network_records outerNodes : List Node from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.outerNodes"]

load_network_records firewallNodes : List Node from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.firewallNodes"]

load_network_records blackNodes : List Node from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.blackNodes"]

load_network_records grayFirewallNodes : List Node from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.grayFirewallNodes"]

load_network_records innerNodes : List Node from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.innerNodes"]

def outerSide (node : Node) : Nat := [0, 5, 5, 5, 5, 5, 6, 5, 5, 5, 5, 11, 20, 20, 20, 20, 20, 17, 20, 20, 20, 20, 22][node.val]!

def graySide (node : Node) : Nat := [0, 1, 2, 5, 5, 5, 6, 7, 8, 8, 8, 11, 12, 13, 15, 15, 15, 17, 18, 19, 19, 19, 22][node.val]!

def level (node : Node) : Nat := [0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2][node.val]!

def edge (a b : Node) : Prop := (a,b) ∈ edges

def grayEdge (a b : Node) : Prop := (a,b) ∈ grayEdges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def grayFirewall (a : Node) : Prop := a ∈ grayFirewallNodes

def untrustedBlack : Bool := true

def publicInternet : Bool := true

def grayRequired : Bool := true

def grayConnection : Node → Node → Prop := Relation.ReflTransGen grayEdge

def outer (a : Node) : Prop := a ∈ outerNodes

def black (a : Node) : Prop := a ∈ blackNodes

def inner (a : Node) : Prop := a ∈ innerNodes

def insideAttachment (a b : Node) : Prop := (a,b) ∈ insideAttachments

def outsideAttachment (a b : Node) : Prop := (a,b) ∈ outsideAttachments

def externalConnection (_ _ : Node) : Prop := False

lemma nonempty_outer_inventory : outerNodes ≠ [] := by native_decide

lemma nonempty_black_inventory : blackNodes ≠ [] := by native_decide

lemma outer_local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → outerSide a = outerSide b := by unfold edge edges firewall firewallNodes outerSide; native_decide

lemma outer_start_clear : ∀ a, a ∈ outerNodes → ¬ firewall a := by unfold outerNodes firewall firewallNodes; native_decide

lemma outer_sides_differ : ∀ a b, a ∈ outerNodes → b ∈ blackNodes → outerSide a ≠ outerSide b := by unfold outerNodes blackNodes outerSide; native_decide

theorem outer_firewall_waypointing (a b : Node) (ha : a ∈ outerNodes) (hb : b ∈ blackNodes) : ¬ Relation.ReflTransGen (Waypointing.Avoiding edge firewall) a b := Waypointing.waypointing_of_edge_invariant edge firewall outerSide outer_local_cut (outer_start_clear a ha) (outer_sides_differ a b ha hb)

lemma inside_outside_placement : ∀ o, o ∈ outerNodes → ∃ f b, f ∈ firewallNodes ∧ b ∈ blackNodes ∧ (o,f) ∈ insideAttachments ∧ (f,b) ∈ outsideAttachments := by unfold outerNodes firewallNodes blackNodes insideAttachments outsideAttachments; native_decide

lemma gray_internal_connected (o : Node) (ho : o ∈ outerNodes) : ∃ f, grayFirewall f ∧ Relation.ReflTransGen grayEdge o f := by
  simp only [outerNodes, List.mem_cons, List.not_mem_nil, or_false] at ho
  rcases ho with rfl | rfl | rfl | rfl
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; native_decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 5 4)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 4 1)⟩
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; native_decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 10 9)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 9 1)⟩
  · exact ⟨12, by unfold grayFirewall grayFirewallNodes; native_decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 16 15)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 15 12)⟩
  · exact ⟨12, by unfold grayFirewall grayFirewallNodes; native_decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 21 20)).tail (by unfold grayEdge grayEdges; native_decide : grayEdge 20 12)⟩

theorem snapshot_public_internet_RG034 : Requirements.msc_outer_firewall_placement untrustedBlack publicInternet grayRequired edge grayConnection outer firewall black grayFirewall inner insideAttachment outsideAttachment externalConnection := Requirements.outer_firewall_placement_from_local_checks outerSide (fun _ => rfl) (by intro a b h; apply Relation.ReflTransGen.single; have checked : ∀ a b : Node, (a,b) ∈ insideAttachments ∨ (a,b) ∈ outsideAttachments ∨ False → edge a b := (by unfold insideAttachments outsideAttachments edge edges; native_decide); exact checked a b h) inside_outside_placement gray_internal_connected (fun _ => outer_local_cut) (fun _ => outer_start_clear) (fun _ => outer_sides_differ)

lemma gray_local_cut : ∀ a b, grayEdge a b → ¬ grayFirewall a → ¬ grayFirewall b → graySide a = graySide b := by unfold grayEdge grayEdges grayFirewall grayFirewallNodes graySide; native_decide

lemma inner_start_clear : ∀ a, a ∈ innerNodes → ¬ grayFirewall a := by unfold innerNodes grayFirewall grayFirewallNodes; native_decide

lemma gray_sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → graySide a ≠ graySide b := by unfold innerNodes level graySide; native_decide

theorem cross_level_gray_waypointing (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Waypointing.Avoiding grayEdge grayFirewall) a b := Waypointing.waypointing_of_edge_invariant grayEdge grayFirewall graySide gray_local_cut (inner_start_clear a ha) (gray_sides_differ a b ha hb different)

load_network_records ipv6Disablement : List (Nat × Nat) from "../../data/evidence/ProfileBaseline_Topology.json" ["TDN.Deployments.ProfileBaseline_Topology.ipv6Disablement"]

theorem all_recorded_ipv6_interfaces_disabled : ∀ setting ∈ ipv6Disablement, setting.1 = 1 ∧ setting.2 = 0 := by unfold ipv6Disablement; native_decide

end TDN.Deployments.ProfileBaseline_Topology
