import TDN.Evidence.DomainTypes

namespace TDN.Imported.Domains

set_option maxRecDepth 100000

set_option maxHeartbeats 0

namespace shared_same_level

def levels : List SecurityLevel := [⟨"SECRET", {}, {"US_ONLY"}, {}⟩]

def networks : List Evidence.DeclaredRedNetwork := [⟨⟨"RED-A-NETWORK-1", "A", ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, {"I_A1"}⟩, "NETWORK-1", "inner-s1", ["NET-005-C01"]⟩, ⟨⟨"RED-A-NETWORK-2", "A", ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, {"I_A2"}⟩, "NETWORK-2", "inner-s2", ["NET-005-C01"]⟩, ⟨⟨"RED-B-NETWORK-1", "B", ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, {"I_B1"}⟩, "NETWORK-1", "inner-s1", ["NET-005-C01"]⟩, ⟨⟨"RED-B-NETWORK-2", "B", ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, {"I_B2"}⟩, "NETWORK-2", "inner-s2", ["NET-005-C01"]⟩]

theorem declared_dedicated_inner_assignments : DedicatedInnerAssignments (networks.map Evidence.DeclaredRedNetwork.identity) := by unfold DedicatedInnerAssignments networks; decide

theorem declared_distinct_domains_same_full_level : Evidence.DifferentDomainsAtSameLevel networks := by unfold Evidence.DifferentDomainsAtSameLevel networks; decide

end shared_same_level

namespace shared_four_levels

def levels : List SecurityLevel := [⟨"TOP_SECRET", {}, {}, {}⟩, ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, ⟨"SECRET", {}, {"COALITION"}, {}⟩, ⟨"UNCLASSIFIED", {}, {}, {}⟩]

def networks : List Evidence.DeclaredRedNetwork := [⟨⟨"RED-A-NETWORK-1", "A", ⟨"TOP_SECRET", {}, {}, {}⟩, {"I_A1"}⟩, "NETWORK-1", "inner-s1", ["NET-006-C01"]⟩, ⟨⟨"RED-A-NETWORK-2", "A", ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, {"I_A2"}⟩, "NETWORK-2", "inner-s2", ["NET-006-C01"]⟩, ⟨⟨"RED-B-NETWORK-1", "B", ⟨"TOP_SECRET", {}, {}, {}⟩, {"I_B1"}⟩, "NETWORK-1", "inner-s1", ["NET-006-C01"]⟩, ⟨⟨"RED-B-NETWORK-2", "B", ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, {"I_B2"}⟩, "NETWORK-2", "inner-s2", ["NET-006-C01"]⟩, ⟨⟨"RED-A-NETWORK-3", "A", ⟨"SECRET", {}, {"COALITION"}, {}⟩, {"I_A3"}⟩, "NETWORK-3", "inner-secret-coalition", ["NET-006-C01"]⟩, ⟨⟨"RED-B-NETWORK-3", "B", ⟨"SECRET", {}, {"COALITION"}, {}⟩, {"I_B3"}⟩, "NETWORK-3", "inner-secret-coalition", ["NET-006-C01"]⟩, ⟨⟨"RED-A-NETWORK-4", "A", ⟨"UNCLASSIFIED", {}, {}, {}⟩, {"I_A4"}⟩, "NETWORK-4", "inner-unclassified", ["NET-013-C01"]⟩, ⟨⟨"RED-B-NETWORK-4", "B", ⟨"UNCLASSIFIED", {}, {}, {}⟩, {"I_B4"}⟩, "NETWORK-4", "inner-unclassified", ["NET-013-C01"]⟩]

theorem declared_dedicated_inner_assignments : DedicatedInnerAssignments (networks.map Evidence.DeclaredRedNetwork.identity) := by unfold DedicatedInnerAssignments networks; decide

theorem declared_figure_six_levels : Evidence.HasSourceFigureSixLevels levels := by unfold Evidence.HasSourceFigureSixLevels levels; decide

theorem declared_additional_unclassified : ∃ l ∈ levels, l.classification = "UNCLASSIFIED" := by unfold levels; decide

end shared_four_levels

namespace redundant_four_levels

def levels : List SecurityLevel := [⟨"TOP_SECRET", {}, {}, {}⟩, ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, ⟨"SECRET", {}, {"COALITION"}, {}⟩, ⟨"UNCLASSIFIED", {}, {}, {}⟩]

def networks : List Evidence.DeclaredRedNetwork := [⟨⟨"RED-A-NETWORK-1", "A", ⟨"TOP_SECRET", {}, {}, {}⟩, {"I_A1"}⟩, "NETWORK-1", "inner-s1", ["NET-006-C01", "NET-009-C01", "NET-020-C01", "NET-020-C02"]⟩, ⟨⟨"RED-A-NETWORK-2", "A", ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, {"I_A2"}⟩, "NETWORK-2", "inner-s2", ["NET-006-C01", "NET-009-C01", "NET-020-C01", "NET-020-C02"]⟩, ⟨⟨"RED-B-NETWORK-1", "B", ⟨"TOP_SECRET", {}, {}, {}⟩, {"I_B1"}⟩, "NETWORK-1", "inner-s1", ["NET-006-C01", "NET-009-C01", "NET-020-C01", "NET-020-C02"]⟩, ⟨⟨"RED-B-NETWORK-2", "B", ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, {"I_B2"}⟩, "NETWORK-2", "inner-s2", ["NET-006-C01", "NET-009-C01", "NET-020-C01", "NET-020-C02"]⟩, ⟨⟨"RED-A-NETWORK-3", "A", ⟨"SECRET", {}, {"COALITION"}, {}⟩, {"I_A3"}⟩, "NETWORK-3", "inner-secret-coalition", ["NET-006-C01", "NET-009-C01", "NET-020-C01", "NET-020-C02"]⟩, ⟨⟨"RED-B-NETWORK-3", "B", ⟨"SECRET", {}, {"COALITION"}, {}⟩, {"I_B3"}⟩, "NETWORK-3", "inner-secret-coalition", ["NET-006-C01", "NET-009-C01", "NET-020-C01", "NET-020-C02"]⟩, ⟨⟨"RED-A-NETWORK-4", "A", ⟨"UNCLASSIFIED", {}, {}, {}⟩, {"I_A4"}⟩, "NETWORK-4", "inner-unclassified", ["NET-013-C01", "NET-009-C01", "NET-020-C01", "NET-020-C02"]⟩, ⟨⟨"RED-B-NETWORK-4", "B", ⟨"UNCLASSIFIED", {}, {}, {}⟩, {"I_B4"}⟩, "NETWORK-4", "inner-unclassified", ["NET-013-C01", "NET-009-C01", "NET-020-C01", "NET-020-C02"]⟩]

theorem declared_dedicated_inner_assignments : DedicatedInnerAssignments (networks.map Evidence.DeclaredRedNetwork.identity) := by unfold DedicatedInnerAssignments networks; decide

theorem declared_figure_six_levels : Evidence.HasSourceFigureSixLevels levels := by unfold Evidence.HasSourceFigureSixLevels levels; decide

theorem declared_additional_unclassified : ∃ l ∈ levels, l.classification = "UNCLASSIFIED" := by unfold levels; decide

end redundant_four_levels

end TDN.Imported.Domains
