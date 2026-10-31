import TDN.Evidence.DomainTypes

namespace TDN.Imported.NativeSharedBinding

set_option maxRecDepth 100000

def peerLevels : List (SecurityLevel × SecurityLevel) := [(⟨"TOP_SECRET", {}, {}, {}⟩, ⟨"TOP_SECRET", {}, {}, {}⟩), (⟨"SECRET", {}, {"US_ONLY"}, {}⟩, ⟨"SECRET", {}, {"US_ONLY"}, {}⟩), (⟨"TOP_SECRET", {}, {}, {}⟩, ⟨"TOP_SECRET", {}, {}, {}⟩), (⟨"SECRET", {}, {"US_ONLY"}, {}⟩, ⟨"SECRET", {}, {"US_ONLY"}, {}⟩), (⟨"SECRET", {}, {"COALITION"}, {}⟩, ⟨"SECRET", {}, {"COALITION"}, {}⟩), (⟨"SECRET", {}, {"COALITION"}, {}⟩, ⟨"SECRET", {}, {"COALITION"}, {}⟩), (⟨"UNCLASSIFIED", {}, {}, {}⟩, ⟨"UNCLASSIFIED", {}, {}, {}⟩), (⟨"UNCLASSIFIED", {}, {}, {}⟩, ⟨"UNCLASSIFIED", {}, {}, {}⟩)]

theorem observed_inner_peers_have_same_full_declared_level : peerLevels ≠ [] ∧ ∀ p ∈ peerLevels, p.1 = p.2 := by unfold peerLevels; decide

def capturedLevels : List SecurityLevel := [⟨"TOP_SECRET", {}, {}, {}⟩, ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, ⟨"TOP_SECRET", {}, {}, {}⟩, ⟨"SECRET", {}, {"US_ONLY"}, {}⟩, ⟨"SECRET", {}, {"COALITION"}, {}⟩, ⟨"SECRET", {}, {"COALITION"}, {}⟩, ⟨"UNCLASSIFIED", {}, {}, {}⟩, ⟨"UNCLASSIFIED", {}, {}, {}⟩]

theorem captured_source_figure_six_levels : Evidence.HasSourceFigureSixLevels capturedLevels := by unfold Evidence.HasSourceFigureSixLevels capturedLevels; decide

def logicalProbes : List (String × String × String) := [("NETWORK-1", "NETWORK-2", "no_reply"), ("NETWORK-1", "NETWORK-1", "delivered"), ("NETWORK-1", "NETWORK-2", "no_reply"), ("NETWORK-1", "NETWORK-3", "no_reply"), ("NETWORK-1", "NETWORK-3", "no_reply"), ("NETWORK-1", "NETWORK-4", "no_reply"), ("NETWORK-1", "NETWORK-4", "no_reply"), ("NETWORK-2", "NETWORK-1", "no_reply"), ("NETWORK-2", "NETWORK-1", "no_reply"), ("NETWORK-2", "NETWORK-2", "delivered"), ("NETWORK-2", "NETWORK-3", "no_reply"), ("NETWORK-2", "NETWORK-3", "no_reply"), ("NETWORK-2", "NETWORK-4", "no_reply"), ("NETWORK-2", "NETWORK-4", "no_reply"), ("NETWORK-1", "NETWORK-1", "delivered"), ("NETWORK-1", "NETWORK-2", "no_reply"), ("NETWORK-1", "NETWORK-2", "no_reply"), ("NETWORK-1", "NETWORK-3", "no_reply"), ("NETWORK-1", "NETWORK-3", "no_reply"), ("NETWORK-1", "NETWORK-4", "no_reply"), ("NETWORK-1", "NETWORK-4", "no_reply"), ("NETWORK-2", "NETWORK-1", "no_reply"), ("NETWORK-2", "NETWORK-2", "delivered"), ("NETWORK-2", "NETWORK-1", "no_reply"), ("NETWORK-2", "NETWORK-3", "no_reply"), ("NETWORK-2", "NETWORK-3", "no_reply"), ("NETWORK-2", "NETWORK-4", "no_reply"), ("NETWORK-2", "NETWORK-4", "no_reply"), ("NETWORK-3", "NETWORK-1", "no_reply"), ("NETWORK-3", "NETWORK-2", "no_reply"), ("NETWORK-3", "NETWORK-1", "no_reply"), ("NETWORK-3", "NETWORK-2", "no_reply"), ("NETWORK-3", "NETWORK-3", "delivered"), ("NETWORK-3", "NETWORK-4", "no_reply"), ("NETWORK-3", "NETWORK-4", "no_reply"), ("NETWORK-3", "NETWORK-1", "no_reply"), ("NETWORK-3", "NETWORK-2", "no_reply"), ("NETWORK-3", "NETWORK-1", "no_reply"), ("NETWORK-3", "NETWORK-2", "no_reply"), ("NETWORK-3", "NETWORK-3", "delivered"), ("NETWORK-3", "NETWORK-4", "no_reply"), ("NETWORK-3", "NETWORK-4", "no_reply"), ("NETWORK-4", "NETWORK-1", "no_reply"), ("NETWORK-4", "NETWORK-2", "no_reply"), ("NETWORK-4", "NETWORK-1", "no_reply"), ("NETWORK-4", "NETWORK-2", "no_reply"), ("NETWORK-4", "NETWORK-3", "no_reply"), ("NETWORK-4", "NETWORK-3", "no_reply"), ("NETWORK-4", "NETWORK-4", "delivered"), ("NETWORK-4", "NETWORK-1", "no_reply"), ("NETWORK-4", "NETWORK-2", "no_reply"), ("NETWORK-4", "NETWORK-1", "no_reply"), ("NETWORK-4", "NETWORK-2", "no_reply"), ("NETWORK-4", "NETWORK-3", "no_reply"), ("NETWORK-4", "NETWORK-3", "no_reply"), ("NETWORK-4", "NETWORK-4", "delivered")]

theorem recorded_logical_domain_outcomes : ∀ p ∈ logicalProbes, p.2.2 = (if p.1 = p.2.1 then "delivered" else "no_reply") := by unfold logicalProbes; decide

theorem positive_and_negative_witnesses : (∃ p ∈ logicalProbes, p.2.2 = "delivered") ∧ (∃ p ∈ logicalProbes, p.1 ≠ p.2.1 ∧ p.2.2 = "no_reply") := by unfold logicalProbes; decide

end TDN.Imported.NativeSharedBinding
