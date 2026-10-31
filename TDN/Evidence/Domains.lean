import TDN.Import.Command
import TDN.Evidence.DomainTypes

namespace TDN.Imported.Domains

set_option maxRecDepth 100000

set_option maxHeartbeats 0

namespace shared_same_level

tdn_data levels : List SecurityLevel from "../../evidence/lean/Domains.json" ["TDN.Imported.Domains.shared_same_level.levels"]

tdn_data networks : List Evidence.DeclaredRedNetwork from "../../evidence/lean/Domains.json" ["TDN.Imported.Domains.shared_same_level.networks"]

theorem declared_dedicated_inner_assignments : DedicatedInnerAssignments (networks.map Evidence.DeclaredRedNetwork.identity) := by unfold DedicatedInnerAssignments networks; decide

theorem declared_distinct_domains_same_full_level : Evidence.DifferentDomainsAtSameLevel networks := by unfold Evidence.DifferentDomainsAtSameLevel networks; decide

end shared_same_level

namespace shared_four_levels

tdn_data levels : List SecurityLevel from "../../evidence/lean/Domains.json" ["TDN.Imported.Domains.shared_four_levels.levels"]

tdn_data networks : List Evidence.DeclaredRedNetwork from "../../evidence/lean/Domains.json" ["TDN.Imported.Domains.shared_four_levels.networks"]

theorem declared_dedicated_inner_assignments : DedicatedInnerAssignments (networks.map Evidence.DeclaredRedNetwork.identity) := by unfold DedicatedInnerAssignments networks; decide

theorem declared_figure_six_levels : Evidence.HasSourceFigureSixLevels levels := by unfold Evidence.HasSourceFigureSixLevels levels; decide

theorem declared_additional_unclassified : ∃ l ∈ levels, l.classification = "UNCLASSIFIED" := by unfold levels; decide

end shared_four_levels

namespace redundant_four_levels

tdn_data levels : List SecurityLevel from "../../evidence/lean/Domains.json" ["TDN.Imported.Domains.redundant_four_levels.levels"]

tdn_data networks : List Evidence.DeclaredRedNetwork from "../../evidence/lean/Domains.json" ["TDN.Imported.Domains.redundant_four_levels.networks"]

theorem declared_dedicated_inner_assignments : DedicatedInnerAssignments (networks.map Evidence.DeclaredRedNetwork.identity) := by unfold DedicatedInnerAssignments networks; decide

theorem declared_figure_six_levels : Evidence.HasSourceFigureSixLevels levels := by unfold Evidence.HasSourceFigureSixLevels levels; decide

theorem declared_additional_unclassified : ∃ l ∈ levels, l.classification = "UNCLASSIFIED" := by unfold levels; decide

end redundant_four_levels

end TDN.Imported.Domains
