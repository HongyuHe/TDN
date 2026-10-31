import Lean.Elab.Tactic.Omega

namespace TDN.ClockSamples

/-- Offsets are reported estimates in integer microseconds. The three order fields
refer to the collector's command sequence, so changing a guest clock cannot reorder
the evidence. A query alone does not establish that the system clock was adjusted. -/
structure Correction where
  client : String
  source : String
  beforeOrder : Nat
  adjustmentOrder : Nat
  afterOrder : Nat
  beforeOffsetUs : Int
  appliedOffsetUs : Int
  afterOffsetUs : Int
  adjustmentSucceeded : Bool
  deriving DecidableEq, Repr

/-- A successful adjustment is followed by a new query to the same bound source.
The importer binds the three records to that source and the same guest connection. -/
def CorrectedAtSample (toleranceUs : Nat) (record : Correction) : Prop :=
  record.beforeOrder < record.adjustmentOrder ∧
  record.adjustmentOrder < record.afterOrder ∧
  record.adjustmentSucceeded = true ∧
  record.afterOffsetUs.natAbs ≤ toleranceUs

instance (toleranceUs : Nat) (record : Correction) :
    Decidable (CorrectedAtSample toleranceUs record) := by
  unfold CorrectedAtSample
  infer_instance

/-- The measured final offset is strictly smaller than the original displacement.
The result describes these measurements, with no prediction about future drift. -/
theorem successful_sample_improves_displaced_clock {toleranceUs : Nat} {record : Correction}
    (corrected : CorrectedAtSample toleranceUs record)
    (displaced : toleranceUs < record.beforeOffsetUs.natAbs) :
    record.afterOffsetUs.natAbs < record.beforeOffsetUs.natAbs := by
  have bound := corrected.2.2.2
  omega

end TDN.ClockSamples
