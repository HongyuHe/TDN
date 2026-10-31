import TDN.Targets.TimeSynchronization

namespace TDN.Imported.FreshClockCorrections
open ClockSamples Targets

/-- Two separately recorded experiments are preserved in these client identifiers.
The list does not assert one simultaneous combined deployment snapshot. -/
def corrections : List Correction := [⟨"Red-FreeBSD-guest:22222", "10.1.1.20", 11, 12, 13, (-1885433), (-1885447), (26), true⟩,
  ⟨"Red-FreeBSD-guest:22223", "10.2.1.20", 27, 28, 29, (-1639040), (-1639029), (18), true⟩,
  ⟨"Gray-Linux-guest:22452", "10.100.1.20", 18, 19, 20, (-1892951), (-1892956), (-16), true⟩,
  ⟨"Gray-Linux-guest:22453", "10.200.1.20", 40, 41, 42, (-1138502), (-1138509), (3), true⟩]

/-- One millisecond is the selected measurement threshold, not a CP timing bound. -/
lemma corrected_samples : ∀ r ∈ corrections, CorrectedAtSample 1000 r := by decide
lemma initially_displaced : ∀ r ∈ corrections, 1000 < r.beforeOffsetUs.natAbs := by decide

theorem each_observed_correction_reduces_offset :
    ∀ r ∈ corrections, r.afterOffsetUs.natAbs < r.beforeOffsetUs.natAbs :=
  all_checked_clock_corrections_improve_offset corrections 1000 corrected_samples initially_displaced

lemma complete_selected_clock_inventory : corrections.length = 4 := by decide

end TDN.Imported.FreshClockCorrections
