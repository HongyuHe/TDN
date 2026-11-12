import TDN.Import.SnapshotLoader
import TDN.Requirements.MscAddressingRequirements

namespace TDN.Deployments.ProfileBaseline_Addressing

set_option maxRecDepth 100000
set_option maxHeartbeats 0

load_network_records ranges : List (Addressing.Range SecurityLevel) from "../../data/evidence/ProfileBaseline_Addressing.json" ["TDN.Deployments.ProfileBaseline_Addressing.ranges"]

load_network_records pairs : List Requirements.IntendedAddressPair from "../../data/evidence/ProfileBaseline_Addressing.json" ["TDN.Deployments.ProfileBaseline_Addressing.pairs"]

load_network_records policies : List (List PacketPolicy.Rule) from "../../data/evidence/ProfileBaseline_Addressing.json" ["TDN.Deployments.ProfileBaseline_Addressing.policies"]

lemma ranges_valid : ∀ r ∈ ranges, r.low ≤ r.high := by unfold ranges; native_decide
lemma ranges_separated : Addressing.Separated ranges := by unfold Addressing.Separated ranges; native_decide
lemma peers_share_full_level : ∀ p ∈ pairs, Addressing.Owns ranges p.source p.level ∧ Addressing.Owns ranges p.destination p.level := by
  simp [pairs, ranges, Addressing.Owns, Addressing.Contains]
lemma rules_name_intended_peers : ∀ rs ∈ policies, ∀ r ∈ rs, r.verdict = .allow → Requirements.RuleNamesPair pairs r := by
  unfold policies pairs
  native_decide
theorem snapshot_RG014_outer_forwarding : Requirements.msc_gray_addressing_for_level_filtering ranges pairs policies :=
  Requirements.gray_addressing_of_separated_ranges_and_named_rules ranges pairs policies
    ranges_valid ranges_separated peers_share_full_level rules_name_intended_peers

end TDN.Deployments.ProfileBaseline_Addressing
