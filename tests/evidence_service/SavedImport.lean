import TDN.Import.SnapshotLoader
import TDN.Deployments.SnapshotFactTypes
import TDN.Models.IpsecAndAclRuleModel

namespace TDN.ImportTests

load_network_records captured : TDN.Deployments.Snapshot
  from "../../data/evidence/v3-baseline.json" ["snapshot"]

load_network_records grayEdges : List (Nat × Nat)
  from "../../data/evidence/v3-baseline-topology.json" ["grayEdges"]
load_network_records grayFirewalls : List Nat
  from "../../data/evidence/v3-baseline-topology.json" ["grayFirewalls"]
load_network_records grayRegions : List Nat
  from "../../data/evidence/v3-baseline-topology.json" ["grayRegions"]

load_network_records innerForward : List TDN.PacketPolicy.Rule
  from "../../data/evidence/v3-baseline-packet_filters.json" ["NB_I_A1:filters4:FORWARD"]

lemma saved_inventory_has_sources : TDN.Deployments.HasProvenance captured := by
  unfold TDN.Deployments.HasProvenance captured
  decide

lemma every_nonfirewall_gray_edge_keeps_region :
    ∀ edge ∈ grayEdges, edge.1 ∉ grayFirewalls → edge.2 ∉ grayFirewalls →
      grayRegions[edge.1]? = grayRegions[edge.2]? := by decide

lemma imported_filter_is_nonempty : innerForward ≠ [] := by decide

end TDN.ImportTests
