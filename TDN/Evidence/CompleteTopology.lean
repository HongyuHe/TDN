import TDN.Targets.CompleteSpecifications
import TDN.Evidence.NativeBaselineTopology
import TDN.Evidence.NativeSharedTopology

namespace TDN.Imported.CompleteTopology

namespace Baseline
open native_baseline_20261017T2237Z_topology

theorem configured_graph_RG034 :
    Targets.Complete.msc_outer_firewall_placement true true true
      edge (Relation.ReflTransGen grayEdge)
      (fun node => node ∈ outerNodes) firewall (fun node => node ∈ blackNodes)
      grayFirewall (fun node => node ∈ innerNodes)
      (fun a b => (a, b) ∈ insideAttachments)
      (fun a b => (a, b) ∈ outsideAttachments) (fun _ _ => False) :=
  snapshot_public_internet_RG034

lemma nonempty_outer_inventory : outerNodes ≠ [] := by decide

end Baseline

namespace Shared
open native_shared_four_levels_20261017T2240Z_scope_v2_topology

theorem configured_graph_RG034 :
    Targets.Complete.msc_outer_firewall_placement true true true
      edge (Relation.ReflTransGen grayEdge)
      (fun node => node ∈ outerNodes) firewall (fun node => node ∈ blackNodes)
      grayFirewall (fun node => node ∈ innerNodes)
      (fun a b => (a, b) ∈ insideAttachments)
      (fun a b => (a, b) ∈ outsideAttachments) (fun _ _ => False) :=
  snapshot_public_internet_RG034

lemma nonempty_outer_inventory : outerNodes ≠ [] := by decide

end Shared

namespace BypassCheck

abbrev Node := Fin 4
def edge (a b : Node) : Prop := (a, b) ∈ [(0, 1), (1, 2)]
def grayConnection (a b : Node) : Prop := a = 0 ∧ b = 3
def outer (node : Node) : Prop := node = 0
def firewall (node : Node) : Prop := node = 1
def black (node : Node) : Prop := node = 2
def inner (node : Node) : Prop := node = 3
def inside (a b : Node) : Prop := a = 0 ∧ b = 1
def outside (a b : Node) : Prop := a = 1 ∧ b = 2
def side (node : Node) : Nat := if node = 2 then 1 else 0

lemma full_firewall_path :
    Targets.Complete.msc_outer_firewall_placement true true false edge grayConnection
      outer firewall black (fun _ => False) inner inside outside (fun _ _ => False) := by
  apply Targets.outer_firewall_placement_from_local_checks side (fun _ => rfl)
  · intro a b attachment
    apply Relation.ReflTransGen.single
    have checked : ∀ a b : Node, inside a b ∨ outside a b ∨ False → edge a b := by
      unfold inside outside edge
      decide
    exact checked a b attachment
  · change ∀ o, outer o → ∃ f b, firewall f ∧ black b ∧ inside o f ∧ outside f b
    unfold outer firewall black inside outside
    decide
  · change ∀ o, outer o → ∃ i, inner i ∧ grayConnection o i
    unfold outer inner grayConnection
    decide
  · intro _
    unfold edge firewall side
    decide
  · intro _
    unfold outer firewall
    decide
  · intro _
    unfold outer black side
    decide

lemma bypass_edge_rejected :
    ¬ Targets.Complete.msc_outer_firewall_placement true true false
      (fun a b => edge a b ∨ (a = 0 ∧ b = 2)) grayConnection
      outer firewall black (fun _ => False) inner inside outside (fun _ _ => False) := by
  intro conform
  exact conform.2.2.2.1 rfl 0 2 rfl rfl
    (Relation.ReflTransGen.single ⟨Or.inr ⟨rfl, rfl⟩, by unfold firewall; decide⟩)

end BypassCheck
end TDN.Imported.CompleteTopology
