import TDN.Import.Command
import TDN.Semantics.Paths

namespace TDN.Imported.native_samelevel_20261017T2242Z_gray

set_option maxRecDepth 100000

set_option maxHeartbeats 0

abbrev Node := Fin 19

tdn_data edges : List (Node × Node) from "../../evidence/lean/NativeSameLevelGray.json" ["TDN.Imported.native_samelevel_20261017T2242Z_gray.edges"]

tdn_data innerNodes : List Node from "../../evidence/lean/NativeSameLevelGray.json" ["TDN.Imported.native_samelevel_20261017T2242Z_gray.innerNodes"]

tdn_data firewallNodes : List Node from "../../evidence/lean/NativeSameLevelGray.json" ["TDN.Imported.native_samelevel_20261017T2242Z_gray.firewallNodes"]

def edge (a b : Node) : Prop := (a,b) ∈ edges

def firewall (a : Node) : Prop := a ∈ firewallNodes

def level (a : Node) : Nat := [0, 0, 1, 1, 1, 2, 1, 1, 1, 1, 0, 1, 1, 1, 2, 1, 1, 1, 1][a.val]!

def side (a : Node) : Nat := [0, 1, 2, 8, 8, 8, 6, 7, 8, 8, 10, 11, 14, 14, 14, 15, 16, 14, 14][a.val]!

end TDN.Imported.native_samelevel_20261017T2242Z_gray
