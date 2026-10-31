import TDN.Import.Command
import TDN.Targets.Topology

namespace TDN.Imported.FreshBaselineTopology

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 23

tdn_data edges : List (Node × Node) from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.edges"]

tdn_data grayEdges : List (Node × Node) from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.grayEdges"]

tdn_data insideAttachments : List (Node × Node) from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.insideAttachments"]

tdn_data outsideAttachments : List (Node × Node) from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.outsideAttachments"]

tdn_data outerNodes : List Node from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.outerNodes"]

tdn_data firewallNodes : List Node from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.firewallNodes"]

tdn_data blackNodes : List Node from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.blackNodes"]

tdn_data grayFirewallNodes : List Node from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.grayFirewallNodes"]

tdn_data innerNodes : List Node from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.innerNodes"]

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

lemma nonempty_outer_inventory : outerNodes ≠ [] := by decide

lemma nonempty_black_inventory : blackNodes ≠ [] := by decide

lemma outer_local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → outerSide a = outerSide b := by unfold edge edges firewall firewallNodes outerSide; decide

lemma outer_start_clear : ∀ a, a ∈ outerNodes → ¬ firewall a := by unfold outerNodes firewall firewallNodes; decide

lemma outer_sides_differ : ∀ a b, a ∈ outerNodes → b ∈ blackNodes → outerSide a ≠ outerSide b := by unfold outerNodes blackNodes outerSide; decide

theorem all_outer_paths_cross_firewall (a b : Node) (ha : a ∈ outerNodes) (hb : b ∈ blackNodes) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall outerSide outer_local_cut (outer_start_clear a ha) (outer_sides_differ a b ha hb)

lemma inside_outside_placement : ∀ o, o ∈ outerNodes → ∃ f b, f ∈ firewallNodes ∧ b ∈ blackNodes ∧ (o,f) ∈ insideAttachments ∧ (f,b) ∈ outsideAttachments := by unfold outerNodes firewallNodes blackNodes insideAttachments outsideAttachments; decide

lemma gray_internal_connected (o : Node) (ho : o ∈ outerNodes) : ∃ f, grayFirewall f ∧ Relation.ReflTransGen grayEdge o f := by
  simp only [outerNodes, List.mem_cons, List.not_mem_nil, or_false] at ho
  rcases ho with rfl | rfl | rfl | rfl
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 5 4)).tail (by unfold grayEdge grayEdges; decide : grayEdge 4 1)⟩
  · exact ⟨1, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 10 9)).tail (by unfold grayEdge grayEdges; decide : grayEdge 9 1)⟩
  · exact ⟨12, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 16 15)).tail (by unfold grayEdge grayEdges; decide : grayEdge 15 12)⟩
  · exact ⟨12, by unfold grayFirewall grayFirewallNodes; decide, ((Relation.ReflTransGen.refl).tail (by unfold grayEdge grayEdges; decide : grayEdge 21 20)).tail (by unfold grayEdge grayEdges; decide : grayEdge 20 12)⟩

theorem snapshot_public_internet_RG034 : Targets.msc_outer_firewall_placement untrustedBlack publicInternet grayRequired edge grayConnection outer firewall black grayFirewall inner insideAttachment outsideAttachment externalConnection := Targets.outer_firewall_placement_from_local_checks outerSide (fun _ => rfl) (by intro a b h; apply Relation.ReflTransGen.single; have checked : ∀ a b : Node, (a,b) ∈ insideAttachments ∨ (a,b) ∈ outsideAttachments ∨ False → edge a b := (by unfold insideAttachments outsideAttachments edge edges; decide); exact checked a b h) inside_outside_placement gray_internal_connected (fun _ => outer_local_cut) (fun _ => outer_start_clear) (fun _ => outer_sides_differ)

lemma gray_local_cut : ∀ a b, grayEdge a b → ¬ grayFirewall a → ¬ grayFirewall b → graySide a = graySide b := by unfold grayEdge grayEdges grayFirewall grayFirewallNodes graySide; decide

lemma inner_start_clear : ∀ a, a ∈ innerNodes → ¬ grayFirewall a := by unfold innerNodes grayFirewall grayFirewallNodes; decide

lemma gray_sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → graySide a ≠ graySide b := by unfold innerNodes level graySide; decide

theorem cross_level_gray_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding grayEdge grayFirewall) a b := Paths.no_firewall_free_crossing grayEdge grayFirewall graySide gray_local_cut (inner_start_clear a ha) (gray_sides_differ a b ha hb different)

tdn_data ipv6Disablement : List (Nat × Nat) from "../../data/evidence/FreshBaselineTopology.json" ["TDN.Imported.FreshBaselineTopology.ipv6Disablement"]

theorem all_recorded_ipv6_interfaces_disabled : ∀ setting ∈ ipv6Disablement, setting.1 = 1 ∧ setting.2 = 0 := by unfold ipv6Disablement; decide

end TDN.Imported.FreshBaselineTopology
