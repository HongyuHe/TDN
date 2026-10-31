import Mathlib.Data.List.Basic
import Lean.Elab.Tactic.Omega

namespace TDN.RecordCoverage

def Covers {Key Record : Type} (key : Record → Key) (required : List Key) (records : List Record) : Prop :=
  ∀ item ∈ required, ∃ record ∈ records, key record = item

/-- Generating one record from each required object preserves complete inventory coverage. -/
theorem map_covers {Key Record : Type} (key : Record → Key) (required : List Key)
    (build : Key → Record) (identity : ∀ item ∈ required, key (build item) = item) :
    Covers key required (required.map build) := by
  intro item member
  exact ⟨build item, List.mem_map.mpr ⟨item, member, rfl⟩, identity item member⟩

/-- A pointwise transformation preserves coverage when it preserves each record's identity. -/
theorem map_preserves_coverage {Key Record Other : Type} (key : Record → Key)
    (otherKey : Other → Key) (required : List Key) (records : List Record)
    (covered : Covers key required records) (transform : Record → Other)
    (identity : ∀ record ∈ records, otherKey (transform record) = key record) :
    Covers otherKey required (records.map transform) := by
  intro item member
  obtain ⟨record, recorded, same⟩ := covered item member
  exact ⟨transform record, List.mem_map.mpr ⟨record, recorded, rfl⟩,
    (identity record recorded).trans same⟩

/-- A removal guard prevents deletion before a separately supplied calendar retention deadline. -/
theorem not_deleted_during_retention (created deadline now : Nat) (deleted : Option Nat)
    (inWindow : created ≤ now ∧ now < deadline)
    (deletionGuard : ∀ time, deleted = some time → deadline ≤ time)
    (deletionObserved : ∀ time, deleted = some time → time ≤ now) :
    deleted = none := by
  cases deleted with
  | none => rfl
  | some time =>
    have lower := deletionGuard time rfl
    have upper := deletionObserved time rfl
    omega

/-- Checking a deadline shared by several obligations establishes every later deadline. -/
theorem deadline_from_common_bound (time common : Nat) (deadlines : List Nat)
    (within : time ≤ common) (earliest : ∀ deadline ∈ deadlines, common ≤ deadline) :
    ∀ deadline ∈ deadlines, time ≤ deadline :=
  fun deadline member => Nat.le_trans within (earliest deadline member)

end TDN.RecordCoverage
