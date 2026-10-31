import TDN.Import.Command
import TDN.Targets.Addressing

namespace TDN.Imported.FreshBaselineAddressing

set_option maxRecDepth 100000
set_option maxHeartbeats 0

tdn_data ranges : List (Addressing.Range SecurityLevel) from "../../data/evidence/FreshBaselineAddressing.json" ["TDN.Imported.FreshBaselineAddressing.ranges"]

tdn_data pairs : List Targets.IntendedAddressPair from "../../data/evidence/FreshBaselineAddressing.json" ["TDN.Imported.FreshBaselineAddressing.pairs"]

tdn_data policies : List (List PacketPolicy.Rule) from "../../data/evidence/FreshBaselineAddressing.json" ["TDN.Imported.FreshBaselineAddressing.policies"]

lemma ranges_valid : ∀ r ∈ ranges, r.low ≤ r.high := by unfold ranges; decide
lemma ranges_separated : Addressing.Separated ranges := by unfold Addressing.Separated ranges; decide
lemma peers_share_full_level : ∀ p ∈ pairs, Addressing.Owns ranges p.source p.level ∧ Addressing.Owns ranges p.destination p.level := by
  simp [pairs, ranges, Addressing.Owns, Addressing.Contains]
lemma rules_name_intended_peers : ∀ rs ∈ policies, ∀ r ∈ rs, r.verdict = .allow → Targets.RuleNamesPair pairs r := by
  unfold policies pairs
  decide

theorem snapshot_RG014_outer_forwarding : Targets.msc_gray_addressing_for_level_filtering ranges pairs policies :=
  Targets.gray_addressing_of_separated_ranges_and_named_rules ranges pairs policies
    ranges_valid ranges_separated peers_share_full_level rules_name_intended_peers

end TDN.Imported.FreshBaselineAddressing
