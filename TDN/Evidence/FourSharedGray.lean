import TDN.Import.Command
import TDN.Semantics.Paths

namespace TDN.Imported.shared_four_levels_coherent_20261017T2208Z_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 31

tdn_data edges : List (Node × Node) from "../../evidence/lean/FourSharedGray.json" ["TDN.Imported.shared_four_levels_coherent_20261017T2208Z_gray.edges"]

tdn_data innerNodes : List Node from "../../evidence/lean/FourSharedGray.json" ["TDN.Imported.shared_four_levels_coherent_20261017T2208Z_gray.innerNodes"]

tdn_data firewallNodes : List Node from "../../evidence/lean/FourSharedGray.json" ["TDN.Imported.shared_four_levels_coherent_20261017T2208Z_gray.firewallNodes"]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 4, 4, 4, 6, 1, 3, 3, 3, 0, 4, 4, 4, 6, 1, 3, 3, 3, 2, 2, 2, 2, 2, 2, 5, 5, 5, 5, 5, 5][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 3, 9, 9, 6, 7, 8, 9, 10, 11, 12, 30, 30, 15, 16, 17, 30, 19, 20, 9, 22, 23, 30, 25, 26, 9, 28, 29, 30][a.val]!

lemma local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by unfold edge edges firewall firewallNodes side; decide

lemma start_clear : ∀ a, a ∈ innerNodes → ¬ firewall a := by unfold innerNodes firewall firewallNodes; decide

lemma sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → side a ≠ side b := by unfold innerNodes level side; decide

theorem all_cross_level_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall side local_cut (start_clear a ha) (sides_differ a b ha hb different)

end TDN.Imported.shared_four_levels_coherent_20261017T2208Z_gray
