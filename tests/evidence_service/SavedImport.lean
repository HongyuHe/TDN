import TDN.Import.Command
import TDN.Evidence.Types
import TDN.Semantics.PacketPolicy

namespace TDN.ImportTests

tdn_data captured : TDN.Evidence.Snapshot
  from "../../data/evidence/v3-baseline.json" ["snapshot"]

tdn_data grayEdges : List (Nat × Nat)
  from "../../data/evidence/v3-baseline-topology.json" ["grayEdges"]
tdn_data grayFirewalls : List Nat
  from "../../data/evidence/v3-baseline-topology.json" ["grayFirewalls"]
tdn_data grayRegions : List Nat
  from "../../data/evidence/v3-baseline-topology.json" ["grayRegions"]

tdn_data innerForward : List TDN.PacketPolicy.Rule
  from "../../data/evidence/v3-baseline-packet_filters.json" ["NB_I_A1:filters4:FORWARD"]

lemma saved_inventory_has_sources : TDN.Evidence.HasProvenance captured := by
  unfold TDN.Evidence.HasProvenance captured
  decide

lemma every_nonfirewall_gray_edge_keeps_region :
    ∀ edge ∈ grayEdges, edge.1 ∉ grayFirewalls → edge.2 ∉ grayFirewalls →
      grayRegions[edge.1]? = grayRegions[edge.2]? := by decide

lemma imported_filter_is_nonempty : innerForward ≠ [] := by decide

end TDN.ImportTests
