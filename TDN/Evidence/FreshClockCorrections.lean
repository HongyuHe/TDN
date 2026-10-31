import TDN.Import.Command
import TDN.Targets.TimeSynchronization

namespace TDN.Imported.FreshClockCorrections
open ClockSamples Targets

/-- Two separately recorded experiments are preserved in these client identifiers.
The list does not assert one simultaneous combined deployment snapshot. -/
tdn_data corrections : List Correction from "../../evidence/lean/FreshClockCorrections.json" ["TDN.Imported.FreshClockCorrections.corrections"]

/-- One millisecond is the selected measurement threshold, not a CP timing bound. -/
lemma corrected_samples : ∀ r ∈ corrections, CorrectedAtSample 1000 r := by decide
lemma initially_displaced : ∀ r ∈ corrections, 1000 < r.beforeOffsetUs.natAbs := by decide

theorem each_observed_correction_reduces_offset :
    ∀ r ∈ corrections, r.afterOffsetUs.natAbs < r.beforeOffsetUs.natAbs :=
  all_checked_clock_corrections_improve_offset corrections 1000 corrected_samples initially_displaced

lemma complete_selected_clock_inventory : corrections.length = 4 := by decide

end TDN.Imported.FreshClockCorrections
