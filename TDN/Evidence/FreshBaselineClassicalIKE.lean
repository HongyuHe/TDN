import TDN.Import.Command
import TDN.Targets.ClassicalIKE

namespace TDN.Imported.FreshBaselineClassicalIKE
open TDN.Targets

tdn_data offered : List AlgorithmSuite from "../../evidence/lean/FreshBaselineClassicalIKE.json" ["TDN.Imported.FreshBaselineClassicalIKE.offered"]

lemma recorded_offer_inventory_nonempty : offered ≠ [] := by decide

theorem every_recorded_inner_ike_offer_uses_cnsa1 : ∀ suite ∈ offered, CNSA1 suite := by
  apply classical_ike_choices_from_local_checks
  · decide
  · decide
  · unfold offered ClassicalEstablishment; decide
  · unfold offered ApprovedIntegrity; decide

theorem every_selected_recorded_inner_ike_offer_uses_cnsa1
    (suite : AlgorithmSuite) (selected : suite ∈ offered) : CNSA1 suite :=
  negotiated_classical_ike_from_checked_offers offered every_recorded_inner_ike_offer_uses_cnsa1 suite selected

end TDN.Imported.FreshBaselineClassicalIKE
