import TDN.Import.Command
import TDN.Targets.Components

namespace TDN.Imported.FreshOptionalScreening
open Targets

tdn_data controls : List AdditionalControl from "../../evidence/lean/FreshOptionalScreening.json" ["TDN.Imported.FreshOptionalScreening.controls"]

lemma black_placement : ∀ c ∈ controls, c.screeningRouter = true → c.locatedOnBlack = true := by decide
lemma boundary_placement : ∀ c ∈ controls, c.screeningRouter = true → c.insideSolutionBoundary = false := by decide

theorem selected_optional_control_placement : msc_additional_control_permissions controls :=
  additional_controls_from_black_screening_placement controls black_placement boundary_placement

theorem actual_screening_inventory : controls.length = 2 ∧
    ∀ c ∈ controls, c.screeningRouter = true := by decide

end TDN.Imported.FreshOptionalScreening
