import TDN.Import.Command
import TDN.Semantics.Paths

namespace TDN.Imported.baseline_coherent_20261017T2149Z_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 23

tdn_data edges : List (Node × Node) from "../../evidence/lean/CoherentBaselineGray.json" ["TDN.Imported.baseline_coherent_20261017T2149Z_gray.edges"]

tdn_data innerNodes : List Node from "../../evidence/lean/CoherentBaselineGray.json" ["TDN.Imported.baseline_coherent_20261017T2149Z_gray.innerNodes"]

tdn_data firewallNodes : List Node from "../../evidence/lean/CoherentBaselineGray.json" ["TDN.Imported.baseline_coherent_20261017T2149Z_gray.firewallNodes"]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 5, 5, 5, 6, 7, 8, 8, 8, 11, 12, 13, 15, 15, 15, 17, 18, 19, 19, 19, 22][a.val]!

lemma local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by unfold edge edges firewall firewallNodes side; decide

lemma start_clear : ∀ a, a ∈ innerNodes → ¬ firewall a := by unfold innerNodes firewall firewallNodes; decide

lemma sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → side a ≠ side b := by unfold innerNodes level side; decide

theorem all_cross_level_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall side local_cut (start_clear a ha) (sides_differ a b ha hb different)

end TDN.Imported.baseline_coherent_20261017T2149Z_gray
